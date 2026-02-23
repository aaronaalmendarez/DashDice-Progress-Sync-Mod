#ifdef GEODE_IS_WINDOWS
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")
#endif

#include "LocalBridge.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cstdlib>
#include <limits>
#include <optional>
#include <random>
#include <regex>
#include <string>
#include <unordered_map>

#include <fmt/core.h>
#include <Geode/binding/GameLevelManager.hpp>
#include <Geode/binding/GJAccountManager.hpp>
#include <Geode/binding/GJGameLevel.hpp>
#include <Geode/binding/GJSearchObject.hpp>
#include <Geode/binding/GameManager.hpp>
#include <Geode/binding/LevelInfoLayer.hpp>
#include <Geode/loader/Log.hpp>
#include <Geode/loader/Mod.hpp>
#include <Geode/utils/async.hpp>
#include <Geode/utils/web.hpp>

#include "../sync/SyncManager.hpp"

#ifndef GEODE_IS_WINDOWS
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

using namespace geode::prelude;

namespace {

constexpr int kDefaultBridgePort = 47653;
constexpr int kReadBufferSize = 4096;
constexpr int kMaxRequestSize = 128 * 1024;
constexpr int kMaxBodySize = 64 * 1024;

#ifdef GEODE_IS_WINDOWS
std::string toLowerAscii(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return text;
}

std::string getWindowClassName(HWND hwnd) {
    std::array<char, 256> buffer {};
    int len = GetClassNameA(hwnd, buffer.data(), static_cast<int>(buffer.size()));
    if (len <= 0) return "";
    return std::string(buffer.data(), static_cast<size_t>(len));
}

std::string getWindowTitle(HWND hwnd) {
    std::array<char, 512> buffer {};
    int len = GetWindowTextA(hwnd, buffer.data(), static_cast<int>(buffer.size()));
    if (len <= 0) return "";
    return std::string(buffer.data(), static_cast<size_t>(len));
}

bool containsCaseInsensitive(std::string const& haystack, std::string const& needle) {
    if (needle.empty()) return true;
    auto lowerHaystack = toLowerAscii(haystack);
    auto lowerNeedle = toLowerAscii(needle);
    return lowerHaystack.find(lowerNeedle) != std::string::npos;
}

struct WindowSearchContext {
    DWORD processId = 0;
    HWND best = nullptr;
    HWND fallback = nullptr;
    int bestScore = std::numeric_limits<int>::min();
};

BOOL CALLBACK findMainWindowForProcess(HWND hwnd, LPARAM lParam) {
    auto* ctx = reinterpret_cast<WindowSearchContext*>(lParam);
    if (!ctx) return FALSE;

    DWORD windowProcessId = 0;
    GetWindowThreadProcessId(hwnd, &windowProcessId);
    if (windowProcessId != ctx->processId) return TRUE;

    if (!IsWindow(hwnd)) return TRUE;

    if (!ctx->fallback) {
        ctx->fallback = hwnd;
    }

    int score = 0;
    if (IsWindowVisible(hwnd)) score += 3;
    if (GetWindow(hwnd, GW_OWNER) == nullptr) score += 2;

    const auto exStyle = static_cast<unsigned long>(GetWindowLongPtrA(hwnd, GWL_EXSTYLE));
    if ((exStyle & WS_EX_TOOLWINDOW) != 0u) {
        score -= 3;
    }

    const auto className = getWindowClassName(hwnd);
    const auto title = getWindowTitle(hwnd);

    if (containsCaseInsensitive(className, "glfw")) score += 4;
    if (containsCaseInsensitive(title, "geometry dash")) score += 5;

    if (score > ctx->bestScore) {
        ctx->bestScore = score;
        ctx->best = hwnd;
    }

    return TRUE;
}

HWND findCurrentProcessMainWindow() {
    WindowSearchContext ctx;
    ctx.processId = GetCurrentProcessId();
    EnumWindows(findMainWindowForProcess, reinterpret_cast<LPARAM>(&ctx));
    return ctx.best ? ctx.best : ctx.fallback;
}

bool tryBringWindowToFront(HWND hwnd) {
    if (!hwnd) return false;

    // Ensure the window is restored and raised.
    ShowWindowAsync(hwnd, IsIconic(hwnd) ? SW_RESTORE : SW_SHOWNORMAL);
    ShowWindowAsync(hwnd, SW_SHOW);
    PostMessage(hwnd, WM_SYSCOMMAND, SC_RESTORE, 0);
    BringWindowToTop(hwnd);
    SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
    SetWindowPos(hwnd, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
    SetActiveWindow(hwnd);
    SetFocus(hwnd);

    AllowSetForegroundWindow(ASFW_ANY);
    SetForegroundWindow(hwnd);
    if (GetForegroundWindow() == hwnd) {
        return true;
    }

    HWND foreground = GetForegroundWindow();
    DWORD foregroundThread = foreground ? GetWindowThreadProcessId(foreground, nullptr) : 0;
    DWORD currentThread = GetCurrentThreadId();
    if (foregroundThread && foregroundThread != currentThread) {
        AttachThreadInput(foregroundThread, currentThread, TRUE);
        BringWindowToTop(hwnd);
        SetForegroundWindow(hwnd);
        SetFocus(hwnd);
        AttachThreadInput(foregroundThread, currentThread, FALSE);
    }
    if (GetForegroundWindow() == hwnd) {
        return true;
    }

    // Windows foreground lock fallback: inject a minimal ALT key press.
    INPUT altInputs[2] {};
    altInputs[0].type = INPUT_KEYBOARD;
    altInputs[0].ki.wVk = VK_MENU;
    altInputs[1].type = INPUT_KEYBOARD;
    altInputs[1].ki.wVk = VK_MENU;
    altInputs[1].ki.dwFlags = KEYEVENTF_KEYUP;
    SendInput(2, altInputs, sizeof(INPUT));
    BringWindowToTop(hwnd);
    SetForegroundWindow(hwnd);
    if (GetForegroundWindow() == hwnd) {
        return true;
    }

    using SwitchToThisWindowFn = void(WINAPI*)(HWND, BOOL);
    auto* user32 = GetModuleHandleA("user32.dll");
    if (user32) {
        auto switchToWindow = reinterpret_cast<SwitchToThisWindowFn>(GetProcAddress(user32, "SwitchToThisWindow"));
        if (switchToWindow) {
            switchToWindow(hwnd, TRUE);
        }
    }

    return GetForegroundWindow() == hwnd;
}

bool focusCurrentProcessWindow() {
    HWND hwnd = findCurrentProcessMainWindow();
    if (!hwnd) return false;

    if (tryBringWindowToFront(hwnd)) {
        return true;
    }

    FLASHWINFO flash {};
    flash.cbSize = sizeof(FLASHWINFO);
    flash.hwnd = hwnd;
    flash.dwFlags = FLASHW_TRAY | FLASHW_TIMERNOFG;
    flash.uCount = 3;
    FlashWindowEx(&flash);
    return false;
}
#endif

std::string trim(std::string const& in) {
    auto begin = in.begin();
    while (begin != in.end() && std::isspace(static_cast<unsigned char>(*begin))) {
        ++begin;
    }
    auto end = in.end();
    while (end != begin && std::isspace(static_cast<unsigned char>(*(end - 1)))) {
        --end;
    }
    return std::string(begin, end);
}

bool isHttpUrlLike(std::string const& value) {
    auto lower = trim(value);
    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return lower.rfind("http://", 0) == 0 || lower.rfind("https://", 0) == 0;
}

std::string deriveOpenEndpointFromSync(std::string const& syncEndpoint) {
    auto sync = trim(syncEndpoint);
    auto schemePos = sync.find("://");
    if (sync.empty() || schemePos == std::string::npos) {
        return "";
    }

    auto pathPos = sync.find('/', schemePos + 3);
    auto origin = pathPos == std::string::npos ? sync : sync.substr(0, pathPos);
    return fmt::format("{}/api/gd/open", origin);
}

std::string originFromUrlLike(std::string const& rawUrl) {
    auto url = trim(rawUrl);
    auto schemePos = url.find("://");
    if (url.empty() || schemePos == std::string::npos) {
        return "";
    }
    auto pathPos = url.find('/', schemePos + 3);
    return pathPos == std::string::npos ? url : url.substr(0, pathPos);
}

std::string deriveSyncEndpointFromOrigin(std::string const& origin) {
    auto value = trim(origin);
    if (value.empty()) return "";
    return fmt::format("{}/api/sync/progress", value);
}

std::string toLowerCopy(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

std::string jsonEscape(std::string input) {
    std::string out;
    out.reserve(input.size() + 16);
    for (char c : input) {
        switch (c) {
        case '\\': out += "\\\\"; break;
        case '"': out += "\\\""; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default: out += c; break;
        }
    }
    return out;
}

std::string randomHex(size_t bytes) {
    static std::mt19937_64 rng { std::random_device {}() };
    static std::uniform_int_distribution<unsigned int> dist(0, 255);
    std::string out;
    out.reserve(bytes * 2);
    for (size_t i = 0; i < bytes; i += 1) {
        auto value = dist(rng);
        out += fmt::format("{:02x}", value);
    }
    return out;
}

std::optional<int> extractJsonInt(std::string const& body, std::string const& key) {
    std::regex re("\"" + key + "\"\\s*:\\s*(-?\\d+)");
    std::smatch match;
    if (!std::regex_search(body, match, re)) return std::nullopt;
    try {
        return std::stoi(match[1].str());
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<std::string> extractJsonString(std::string const& body, std::string const& key) {
    std::regex re("\"" + key + "\"\\s*:\\s*\"([^\"]*)\"");
    std::smatch match;
    if (!std::regex_search(body, match, re)) return std::nullopt;
    return match[1].str();
}

struct HttpRequest {
    std::string method;
    std::string path;
    std::unordered_map<std::string, std::string> headers;
    std::string body;
};

std::optional<HttpRequest> parseHttpRequest(std::string const& raw) {
    auto headerEnd = raw.find("\r\n\r\n");
    if (headerEnd == std::string::npos) return std::nullopt;

    auto headerBlock = raw.substr(0, headerEnd);
    auto body = raw.substr(headerEnd + 4);

    auto lineEnd = headerBlock.find("\r\n");
    if (lineEnd == std::string::npos) return std::nullopt;
    auto requestLine = headerBlock.substr(0, lineEnd);

    auto firstSpace = requestLine.find(' ');
    if (firstSpace == std::string::npos) return std::nullopt;
    auto secondSpace = requestLine.find(' ', firstSpace + 1);
    if (secondSpace == std::string::npos) return std::nullopt;

    HttpRequest req;
    req.method = requestLine.substr(0, firstSpace);
    req.path = requestLine.substr(firstSpace + 1, secondSpace - firstSpace - 1);
    req.body = body;

    size_t cursor = lineEnd + 2;
    while (cursor < headerBlock.size()) {
        auto next = headerBlock.find("\r\n", cursor);
        auto line = headerBlock.substr(cursor, next == std::string::npos ? std::string::npos : next - cursor);
        auto sep = line.find(':');
        if (sep != std::string::npos) {
            auto key = toLowerCopy(trim(line.substr(0, sep)));
            auto value = trim(line.substr(sep + 1));
            req.headers[key] = value;
        }
        if (next == std::string::npos) break;
        cursor = next + 2;
    }
    return req;
}

std::string reasonPhrase(int status) {
    switch (status) {
    case 200: return "OK";
    case 202: return "Accepted";
    case 204: return "No Content";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 409: return "Conflict";
    case 422: return "Unprocessable Entity";
    case 500: return "Internal Server Error";
    default: return "OK";
    }
}

#ifdef GEODE_IS_WINDOWS
using SocketHandle = SOCKET;
using SocketLen = int;
constexpr SocketHandle kInvalidSocket = INVALID_SOCKET;
void closeSocket(SocketHandle sock) {
    if (sock != INVALID_SOCKET) {
        closesocket(sock);
    }
}
#else
using SocketHandle = int;
using SocketLen = socklen_t;
constexpr SocketHandle kInvalidSocket = -1;
void closeSocket(SocketHandle sock) {
    if (sock >= 0) {
        close(sock);
    }
}
#endif

} // namespace

namespace dashdice {

LocalBridge& LocalBridge::get() {
    static LocalBridge instance;
    return instance;
}

bool LocalBridge::isBridgeEnabled() const {
    return Mod::get()->getSettingValue<bool>("enable-bridge");
}

bool LocalBridge::isDebugEnabled() const {
    return Mod::get()->getSettingValue<bool>("debug-logs");
}

int LocalBridge::bridgePort() const {
    int configured = Mod::get()->getSettingValue<int>("bridge-port");
    if (configured < 1024 || configured > 65535) {
        return kDefaultBridgePort;
    }
    return configured;
}

std::string LocalBridge::bridgeAllowedOriginsCsv() const {
    return Mod::get()->getSettingValue<std::string>("bridge-allowed-origins");
}

std::string LocalBridge::openEndpoint() const {
    auto syncEndpoint = Mod::get()->getSettingValue<std::string>("server-url");
    auto derived = deriveOpenEndpointFromSync(syncEndpoint);
    if (!derived.empty()) {
        return derived;
    }
    return "https://dash.motioncore.xyz/api/gd/open";
}

std::string LocalBridge::requestId() {
    return randomHex(8);
}

void LocalBridge::onMenuReady() {
    this->ensureServerState();
}

void LocalBridge::openLevelFromRemote(int levelId) {
    if (levelId <= 0) return;
    this->queueOpenLevel(levelId);
}

void LocalBridge::shutdown() {
    this->stopServer();
}

void LocalBridge::ensureServerState() {
    if (!this->isBridgeEnabled()) {
        this->stopServer();
        return;
    }

    const int port = this->bridgePort();
    if (m_running.load() && m_serverPort == port) {
        return;
    }

    this->stopServer();
    if (!this->startServer(port)) {
        log::warn("[DashDiceBridge] Failed to start on 127.0.0.1:{}", port);
    }
}

bool LocalBridge::startServer(int port) {
#ifdef GEODE_IS_WINDOWS
    WSADATA wsaData {};
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return false;
    }
#endif

    SocketHandle listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSock == kInvalidSocket) {
        return false;
    }

    int yes = 1;
    setsockopt(listenSock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<char const*>(&yes), sizeof(yes));

    sockaddr_in addr {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(listenSock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        closeSocket(listenSock);
        return false;
    }
    if (listen(listenSock, 8) != 0) {
        closeSocket(listenSock);
        return false;
    }

    m_bridgeToken = randomHex(16);
    m_serverPort = port;
    m_listenFd = static_cast<std::intptr_t>(listenSock);
    m_running.store(true);
    m_serverThread = std::thread([this]() {
        this->serverLoop();
    });

    if (this->isDebugEnabled()) {
        log::debug("[DashDiceBridge] Listening on 127.0.0.1:{}", port);
    }
    return true;
}

void LocalBridge::stopServer() {
    m_running.store(false);
    auto sock = static_cast<SocketHandle>(m_listenFd);
    if (sock != kInvalidSocket) {
        closeSocket(sock);
        m_listenFd = -1;
    }
    if (m_serverThread.joinable()) {
        m_serverThread.join();
    }
#ifdef GEODE_IS_WINDOWS
    WSACleanup();
#endif
}

void LocalBridge::serverLoop() {
    auto listenSock = static_cast<SocketHandle>(m_listenFd);
    while (m_running.load()) {
        sockaddr_in clientAddr {};
        SocketLen len = sizeof(clientAddr);
        auto client = accept(listenSock, reinterpret_cast<sockaddr*>(&clientAddr), &len);
        if (client == kInvalidSocket) {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
            continue;
        }
        this->handleClient(static_cast<int>(client));
        closeSocket(client);
    }
}

void LocalBridge::handleClient(int clientFd) {
    auto client = static_cast<SocketHandle>(clientFd);

    std::string raw;
    raw.reserve(8192);
    std::array<char, kReadBufferSize> chunk {};
    size_t contentLength = 0;
    bool parsedHeaders = false;

    while (raw.size() < kMaxRequestSize) {
        auto read = recv(client, chunk.data(), static_cast<int>(chunk.size()), 0);
        if (read <= 0) break;
        raw.append(chunk.data(), static_cast<size_t>(read));

        auto headerEnd = raw.find("\r\n\r\n");
        if (!parsedHeaders && headerEnd != std::string::npos) {
            parsedHeaders = true;
            auto headerBlock = raw.substr(0, headerEnd);
            std::regex clRe(R"(content-length:\s*(\d+))", std::regex::icase);
            std::smatch m;
            if (std::regex_search(headerBlock, m, clRe)) {
                contentLength = static_cast<size_t>(std::strtoul(m[1].str().c_str(), nullptr, 10));
                if (contentLength > kMaxBodySize) {
                    break;
                }
            }
        }

        if (parsedHeaders) {
            auto headerEnd2 = raw.find("\r\n\r\n");
            if (headerEnd2 != std::string::npos) {
                const auto bodyLen = raw.size() - (headerEnd2 + 4);
                if (bodyLen >= contentLength) {
                    break;
                }
            }
        }
    }

    auto reqOpt = parseHttpRequest(raw);
    if (!reqOpt) {
        std::string body = R"({"ok":false,"error":"Malformed request."})";
        std::string response =
            "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: " +
            std::to_string(body.size()) +
            "\r\nConnection: close\r\n\r\n" + body;
        send(client, response.c_str(), static_cast<int>(response.size()), 0);
        return;
    }
    auto req = *reqOpt;

    auto originIt = req.headers.find("origin");
    std::string origin = originIt != req.headers.end() ? originIt->second : "";
    auto sendJson = [&](int status, std::string const& jsonBody, bool allowCorsHeaders) {
        std::string headers = fmt::format(
            "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
            status,
            reasonPhrase(status),
            jsonBody.size()
        );

        if (allowCorsHeaders && !origin.empty() && this->isOriginAllowed(origin)) {
            headers += fmt::format("Access-Control-Allow-Origin: {}\r\n", origin);
            headers += "Vary: Origin\r\n";
            headers += "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n";
            headers += "Access-Control-Allow-Headers: Content-Type, X-DashDice-Bridge-Token\r\n";
        }

        headers += "\r\n";
        auto packet = headers + jsonBody;
        send(client, packet.c_str(), static_cast<int>(packet.size()), 0);
    };

    if (req.method == "OPTIONS") {
        if (!origin.empty() && !this->isOriginAllowed(origin)) {
            sendJson(403, R"({"ok":false,"error":"Origin not allowed."})", true);
            return;
        }
        sendJson(204, "", true);
        return;
    }

    if (!origin.empty() && !this->isOriginAllowed(origin)) {
        sendJson(403, R"({"ok":false,"error":"Origin not allowed."})", true);
        return;
    }

    if (req.method == "GET" && req.path == "/health") {
        auto body = fmt::format(
            R"({{"ok":true,"token":"{}","message":"Bridge ready","port":{},"openEndpoint":"{}","pairing":true}})",
            jsonEscape(m_bridgeToken),
            m_serverPort,
            jsonEscape(this->openEndpoint())
        );
        sendJson(200, body, true);
        return;
    }

    auto tokenIt = req.headers.find("x-dashdice-bridge-token");
    std::string token = tokenIt != req.headers.end() ? tokenIt->second : "";
    if (token != m_bridgeToken) {
        sendJson(401, R"({"ok":false,"error":"Invalid bridge token."})", true);
        return;
    }

    if (req.method == "POST" && req.path == "/open-level") {
        auto levelId = extractJsonInt(req.body, "levelId").value_or(0);
        if (levelId <= 0) {
            sendJson(400, R"({"ok":false,"accepted":false,"message":"Invalid levelId."})", true);
            return;
        }

        this->queueOpenLevel(levelId);
        auto body = fmt::format(
            R"({{"ok":true,"accepted":true,"message":"Level {} opening in Geometry Dash."}})",
            levelId
        );
        sendJson(202, body, true);
        return;
    }

    if (req.method == "POST" && req.path == "/focus") {
        this->queueFocusWindow();
        sendJson(202, R"({"ok":true,"accepted":true,"message":"Geometry Dash focus requested."})", true);
        return;
    }

    if (req.method == "POST" && req.path == "/pair-request") {
        auto code = extractJsonString(req.body, "code").value_or("");
        auto claimUrl = extractJsonString(req.body, "claimUrl").value_or("");
        auto requestOrigin = extractJsonString(req.body, "origin").value_or(origin);

        if (code.size() != 6 || !std::all_of(code.begin(), code.end(), [](unsigned char ch) { return std::isdigit(ch) != 0; })) {
            sendJson(400, R"({"ok":false,"accepted":false,"message":"Pair code must be 6 digits."})", true);
            return;
        }
        if (claimUrl.empty()) {
            sendJson(400, R"({"ok":false,"accepted":false,"message":"Missing claimUrl."})", true);
            return;
        }

        this->queuePairPrompt(code, claimUrl, requestOrigin);
        sendJson(202, R"({"ok":true,"accepted":true,"message":"Check Geometry Dash for confirmation."})", true);
        return;
    }

    sendJson(404, R"({"ok":false,"error":"Not found."})", true);
}

std::unordered_set<std::string> LocalBridge::parseAllowedOrigins() const {
    std::unordered_set<std::string> out;
    auto csv = this->bridgeAllowedOriginsCsv();
    size_t cursor = 0;
    while (cursor <= csv.size()) {
        auto next = csv.find(',', cursor);
        auto piece = csv.substr(cursor, next == std::string::npos ? std::string::npos : next - cursor);
        auto value = trim(piece);
        if (!value.empty()) {
            if (!value.empty() && value.back() == '/') {
                value.pop_back();
            }
            out.insert(value);
        }
        if (next == std::string::npos) break;
        cursor = next + 1;
    }
    return out;
}

bool LocalBridge::isOriginAllowed(std::string const& origin) const {
    if (origin.empty()) return true;
    auto normalized = origin;
    if (!normalized.empty() && normalized.back() == '/') {
        normalized.pop_back();
    }

    auto allowed = this->parseAllowedOrigins();
    if (allowed.contains("*")) return true;
    return allowed.contains(normalized);
}

void LocalBridge::queueOpenLevel(int levelId) {
    Loader::get()->queueInMainThread([this, levelId]() {
        this->focusGameWindow();
        this->openLevelInGame(levelId);
    });
}

void LocalBridge::queueFocusWindow() {
    Loader::get()->queueInMainThread([this]() {
        this->focusGameWindow();
    });
}

void LocalBridge::focusGameWindow() {
#ifdef GEODE_IS_WINDOWS
    const bool focused = focusCurrentProcessWindow();
    if (this->isDebugEnabled()) {
        if (focused) {
            log::debug("[DashDiceBridge] Focused Geometry Dash window");
        } else {
            log::debug("[DashDiceBridge] Requested Geometry Dash window focus (foreground lock may apply)");
        }
    }
#endif
}

void LocalBridge::openResolvedLevel(GJGameLevel* level) {
    if (level == nullptr) return;
    auto* scene = LevelInfoLayer::scene(level, false);
    if (scene == nullptr) return;
    if (this->isDebugEnabled()) {
        log::debug("[DashDiceBridge] Opened level {} scene", static_cast<int>(level->m_levelID.value()));
    }
    CCDirector::sharedDirector()->replaceScene(scene);
}

void LocalBridge::restoreLevelDelegate() {
    auto* manager = GameLevelManager::sharedState();
    if (manager) {
        manager->m_levelManagerDelegate = m_prevLevelManagerDelegate;
    }
    m_prevLevelManagerDelegate = nullptr;
    m_pendingOpenLevelId = 0;
}

void LocalBridge::openLevelInGame(int levelId) {
    auto* manager = GameLevelManager::sharedState();
    if (!manager) return;

    if (auto* saved = manager->getSavedLevel(levelId)) {
        if (saved->m_levelID.value() == levelId) {
            if (this->isDebugEnabled()) {
                log::debug("[DashDiceBridge] Opened level {} immediately from cache", levelId);
            }
            this->openResolvedLevel(saved);
            return;
        }
    }

    m_pendingOpenLevelId = levelId;
    m_prevLevelManagerDelegate = manager->m_levelManagerDelegate;
    manager->m_levelManagerDelegate = this;
    auto* search = GJSearchObject::create(SearchType::Search, fmt::format("{}", levelId));
    manager->getOnlineLevels(search);

    if (this->isDebugEnabled()) {
        log::debug("[DashDiceBridge] Requested level metadata via getOnlineLevels(SearchType::Search, '{}')", levelId);
    }
}

void LocalBridge::completePendingOpen() {
    if (m_pendingOpenLevelId <= 0) return;
    auto* manager = GameLevelManager::sharedState();
    if (!manager) {
        this->restoreLevelDelegate();
        return;
    }

    const int levelId = m_pendingOpenLevelId;
    if (auto* resolved = manager->getSavedLevel(levelId)) {
        if (resolved->m_levelID.value() == levelId) {
            this->openResolvedLevel(resolved);
        }
    }
    this->restoreLevelDelegate();
}

void LocalBridge::loadLevelsFinished(cocos2d::CCArray* levels, char const* key) {
    this->loadLevelsFinished(levels, key, 0);
}

void LocalBridge::loadLevelsFailed(char const* key) {
    this->loadLevelsFailed(key, 0);
}

void LocalBridge::loadLevelsFinished(cocos2d::CCArray* levels, char const*, int) {
    auto* manager = GameLevelManager::sharedState();
    if (!manager || m_pendingOpenLevelId <= 0) {
        this->restoreLevelDelegate();
        return;
    }

    const int levelId = m_pendingOpenLevelId;
    GJGameLevel* match = nullptr;
    if (levels) {
        for (auto* obj : CCArrayExt<cocos2d::CCObject*>(levels)) {
            auto* level = typeinfo_cast<GJGameLevel*>(obj);
            if (!level) continue;
            if (static_cast<int>(level->m_levelID.value()) == levelId) {
                match = level;
                break;
            }
        }
    }

    if (match) {
        manager->saveLevel(match);
        this->openResolvedLevel(match);
        if (this->isDebugEnabled()) {
            log::debug("[DashDiceBridge] Replaced placeholder with downloaded level {} page", levelId);
        }
    } else if (this->isDebugEnabled()) {
        log::warn("[DashDiceBridge] Could not resolve level {} from download response", levelId);
    }

    this->completePendingOpen();
}

void LocalBridge::loadLevelsFailed(char const*, int) {
    if (this->isDebugEnabled() && m_pendingOpenLevelId > 0) {
        log::warn("[DashDiceBridge] Failed to download level {}", m_pendingOpenLevelId);
    }
    this->restoreLevelDelegate();
}

void LocalBridge::setupPageInfo(gd::string, char const*) {}

void LocalBridge::queuePairPrompt(std::string code, std::string claimUrl, std::string origin) {
    Loader::get()->queueInMainThread([this, code = std::move(code), claimUrl = std::move(claimUrl), origin = std::move(origin)]() {
        this->focusGameWindow();
        auto message = fmt::format(
            "Allow DashDice to sync this Geometry Dash client?\n\nCode: {}\nOrigin: {}\n\nThis will auto-apply your endpoint, open endpoint, allowed origins, and API key.",
            code,
            origin.empty() ? "unknown" : origin
        );
        geode::createQuickPopup(
            "DashDice Pair Request",
            message,
            "Cancel",
            "Allow",
            [this, code, claimUrl, origin](FLAlertLayer*, bool allow) {
                if (!allow) return;
                this->beginPairClaim(code, claimUrl, origin);
            },
            true
        );
    });
}

void LocalBridge::beginPairClaim(std::string code, std::string claimUrl, std::string origin) {
    {
        std::lock_guard<std::mutex> guard(m_stateMutex);
        if (m_pairClaimInFlight) {
            geode::createQuickPopup(
                "DashDice Pairing",
                "A pairing request is already in progress.",
                "OK",
                nullptr,
                [](FLAlertLayer*, bool) {},
                true
            );
            return;
        }
        m_pairClaimInFlight = true;
    }

    if (this->isDebugEnabled()) {
        log::debug("[DashDiceBridge] Claiming pair code {} from {}", code, origin);
    }

    async::spawn(this->claimPairAsync(code, claimUrl), [this](Result<> result) {
        {
            std::lock_guard<std::mutex> guard(m_stateMutex);
            m_pairClaimInFlight = false;
        }

        if (GEODE_UNWRAP_IF_ERR(err, result)) {
            geode::createQuickPopup(
                "DashDice Pairing",
                fmt::format("Pairing failed: {}", err),
                "OK",
                nullptr,
                [](FLAlertLayer*, bool) {},
                true
            );
            return;
        }

        SyncManager::get().onMenuReady();
        geode::createQuickPopup(
            "DashDice Pairing",
            "Connected successfully. Sync settings were applied automatically.",
            "OK",
            nullptr,
            [](FLAlertLayer*, bool) {},
            true
        );
    });
}

arc::Future<Result<>> LocalBridge::claimPairAsync(std::string code, std::string claimUrl) {
    auto* accountMgr = GJAccountManager::sharedState();
    auto* gameMgr = GameManager::sharedState();
    auto deviceName = gameMgr && !gameMgr->m_playerName.empty()
        ? fmt::format("GD-{}", gameMgr->m_playerName)
        : std::string("Geometry Dash");

    matjson::Value payload = matjson::makeObject({
        { "code", code },
        { "deviceName", deviceName },
        { "platform", "windows" },
        { "modVersion", Mod::get()->getVersion().toVString() },
        { "bridgePort", this->bridgePort() },
        { "gdAccountId", accountMgr ? accountMgr->m_accountID : 0 },
    });

    auto response = co_await web::WebRequest()
        .timeout(std::chrono::seconds(12))
        .header("Content-Type", "application/json")
        .bodyJSON(payload)
        .post(claimUrl);

    if (!response.ok()) {
        std::string body;
        if (auto bodyRes = response.string(); bodyRes.isOk()) {
            body = bodyRes.unwrap();
        }
        co_return Err(fmt::format("HTTP {} {}", response.code(), body));
    }

    std::string body;
    if (auto bodyRes = response.string(); bodyRes.isOk()) {
        body = bodyRes.unwrap();
    } else {
        co_return Err("Pairing response was not readable.");
    }

    if (body.find(R"("ok":true)") == std::string::npos && body.find(R"("ok": true)") == std::string::npos) {
        auto err = extractJsonString(body, "error").value_or("Pairing response rejected.");
        co_return Err(err);
    }

    auto syncEndpoint = extractJsonString(body, "syncEndpoint").value_or("");
    auto openEndpoint = extractJsonString(body, "openEndpoint").value_or("");
    auto apiKey = extractJsonString(body, "apiKey").value_or("");
    auto allowedOrigins = extractJsonString(body, "allowedOriginsCsv").value_or("");

    // Pairing should always follow the site origin that initiated pairing
    // (localhost vs production), even if backend fields are stale.
    if (auto claimOrigin = originFromUrlLike(claimUrl); !claimOrigin.empty()) {
        if (auto derivedSync = deriveSyncEndpointFromOrigin(claimOrigin); !derivedSync.empty()) {
            syncEndpoint = derivedSync;
        }
        openEndpoint = fmt::format("{}/api/gd/open", claimOrigin);
    }

    if (openEndpoint.empty()) {
        openEndpoint = deriveOpenEndpointFromSync(syncEndpoint);
    }
    if (syncEndpoint.empty() || apiKey.empty()) {
        co_return Err("Pairing response missing sync endpoint or API key.");
    }

    Mod::get()->setSettingValue<std::string>("server-url", syncEndpoint);
    Mod::get()->setSavedValue<std::string>("persist-setting-server-url", syncEndpoint);
    Mod::get()->setSettingValue<std::string>("api-key", apiKey);
    Mod::get()->setSavedValue<std::string>("persist-setting-api-key", apiKey);
    if (!allowedOrigins.empty()) {
        Mod::get()->setSettingValue<std::string>("bridge-allowed-origins", allowedOrigins);
        Mod::get()->setSavedValue<std::string>("persist-setting-bridge-allowed-origins", allowedOrigins);
    }

    if (this->isDebugEnabled()) {
        log::debug("[DashDiceBridge] Pairing applied settings successfully");
    }

    co_return Ok();
}

} // namespace dashdice
