#include "BridgeServer.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <future>
#include <mutex>
#include <optional>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#ifdef GEODE_IS_WINDOWS
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include <fmt/core.h>
#include <Geode/Geode.hpp>
#include <Geode/binding/GJGameLevel.hpp>
#include <Geode/binding/GameLevelManager.hpp>
#include <Geode/binding/LevelInfoLayer.hpp>
#include <Geode/loader/Log.hpp>
#include <Geode/loader/Mod.hpp>
#include <Geode/loader/Loader.hpp>
#include <matjson.hpp>

#include <cocos2d.h>

using namespace geode::prelude;

namespace {
int64_t nowUnixMs() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::string trim(std::string s) {
    auto isSpace = [](unsigned char c) { return std::isspace(c) != 0; };
    while (!s.empty() && isSpace(static_cast<unsigned char>(s.front()))) {
        s.erase(s.begin());
    }
    while (!s.empty() && isSpace(static_cast<unsigned char>(s.back()))) {
        s.pop_back();
    }
    return s;
}

std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return s;
}

bool startsWith(std::string_view value, std::string_view prefix) {
    return value.size() >= prefix.size() && value.substr(0, prefix.size()) == prefix;
}

std::vector<std::string> splitByComma(std::string const& input) {
    std::vector<std::string> out;
    std::stringstream ss(input);
    std::string part;
    while (std::getline(ss, part, ',')) {
        part = trim(toLower(part));
        if (!part.empty()) {
            out.push_back(part);
        }
    }
    return out;
}

std::string randomHexToken(size_t byteCount) {
    static std::mt19937_64 rng { std::random_device {}() };
    static std::uniform_int_distribution<uint64_t> dist;
    static constexpr char kHex[] = "0123456789abcdef";

    std::string token;
    token.reserve(byteCount * 2);
    for (size_t i = 0; i < byteCount; ++i) {
        uint8_t byte = static_cast<uint8_t>(dist(rng) & 0xFF);
        token.push_back(kHex[(byte >> 4) & 0x0F]);
        token.push_back(kHex[byte & 0x0F]);
    }
    return token;
}

bool isValidNonce(std::string const& nonce) {
    if (nonce.size() < 8 || nonce.size() > 96) {
        return false;
    }
    for (char c : nonce) {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
            continue;
        }
        return false;
    }
    return true;
}

std::optional<int64_t> parseInt64(std::string const& value) {
    if (value.empty()) return std::nullopt;
    char* endPtr = nullptr;
    const auto parsed = std::strtoll(value.c_str(), &endPtr, 10);
    if (endPtr == value.c_str() || *endPtr != '\0') {
        return std::nullopt;
    }
    return parsed;
}

std::string extractOriginFromReferer(std::string const& referer) {
    auto lower = toLower(trim(referer));
    auto schemePos = lower.find("://");
    if (schemePos == std::string::npos) return "";
    auto pathPos = lower.find('/', schemePos + 3);
    if (pathPos == std::string::npos) return lower;
    return lower.substr(0, pathPos);
}

bool isLocalOrigin(std::string const& origin) {
    return startsWith(origin, "http://localhost:") || startsWith(origin, "http://127.0.0.1:") ||
           startsWith(origin, "https://localhost:") || startsWith(origin, "https://127.0.0.1:");
}

std::mutex g_pendingOpenMutex;
std::unordered_set<int> g_pendingOpenLevels;

bool beginPendingOpen(int levelId) {
    std::lock_guard<std::mutex> lock(g_pendingOpenMutex);
    return g_pendingOpenLevels.insert(levelId).second;
}

void endPendingOpen(int levelId) {
    std::lock_guard<std::mutex> lock(g_pendingOpenMutex);
    g_pendingOpenLevels.erase(levelId);
}

bool hasCreatorMetadata(GJGameLevel* level) {
    if (!level) return false;
    auto creator = toLower(trim(level->m_creatorName));
    return !creator.empty() && creator != "-" && creator != "unknown" && creator != "na";
}

GJGameLevel* getBestLevel(GameLevelManager* manager, int levelId) {
    if (!manager) return nullptr;
    if (auto* saved = manager->getSavedLevel(levelId)) return saved;
    return manager->getMainLevel(levelId, false);
}

bool tryOpenLevelPage(int levelId) {
    auto* manager = GameLevelManager::sharedState();
    if (!manager) return false;

    // Only treat as cache-hit when GD confirms level data is downloaded.
    if (!manager->hasDownloadedLevel(levelId)) return false;

    auto* level = getBestLevel(manager, levelId);
    if (!level) return false;

    manager->gotoLevelPage(level);
    return true;
}

bool tryOpenUncachedLevelInfoScene(int levelId) {
    auto* level = GJGameLevel::create();
    if (!level) return false;

    level->m_levelID = levelId;
    level->m_levelName = fmt::format("Level {}", levelId);
    level->m_creatorName = "Unknown";
    level->m_audioTrack = 0;
    level->m_songID = 0;

    auto* scene = LevelInfoLayer::scene(level, false);
    if (!scene) return false;

    auto* director = cocos2d::CCDirector::sharedDirector();
    if (!director) return false;

    director->replaceScene(cocos2d::CCTransitionFade::create(0.2f, scene));
    return true;
}

void scheduleOpenWhenDownloaded(int levelId, bool requireCreatorMetadata) {
    if (!beginPendingOpen(levelId)) {
        return;
    }

    std::thread([levelId, requireCreatorMetadata]() {
        constexpr int kMaxAttempts = 60; // ~9 seconds
        for (int i = 0; i < kMaxAttempts; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(150));

            std::promise<bool> openedPromise;
            auto openedFuture = openedPromise.get_future();
            geode::queueInMainThread([levelId, requireCreatorMetadata, p = std::move(openedPromise)]() mutable {
                auto* manager = GameLevelManager::sharedState();
                if (!manager || !manager->hasDownloadedLevel(levelId)) {
                    p.set_value(false);
                    return;
                }

                auto* level = getBestLevel(manager, levelId);
                if (!level) {
                    p.set_value(false);
                    return;
                }

                if (requireCreatorMetadata && !hasCreatorMetadata(level)) {
                    p.set_value(false);
                    return;
                }

                manager->gotoLevelPage(level);
                p.set_value(true);
            });

            if (openedFuture.get()) {
                geode::queueInMainThread([levelId]() {
                    if (Mod::get()->getSettingValue<bool>("debug-logs")) {
                        log::debug("[DashDiceBridge] Replaced placeholder with downloaded level {} page", levelId);
                    }
                });
                endPendingOpen(levelId);
                return;
            }
        }

        geode::queueInMainThread([levelId, requireCreatorMetadata]() {
            if (requireCreatorMetadata) {
                log::warn("[DashDiceBridge] Timed out waiting for creator metadata on level {}", levelId);
                return;
            }
            log::warn("[DashDiceBridge] Download did not resolve into openable level page for {}", levelId);
        });
        endPendingOpen(levelId);
    }).detach();
}

void queueOpenLevel(int levelId) {
    geode::queueInMainThread([levelId]() {
        auto* manager = GameLevelManager::sharedState();
        if (!manager) {
            log::warn("[DashDiceBridge] GameLevelManager unavailable while opening level {}", levelId);
            return;
        }

        const bool wasDownloaded = manager->hasDownloadedLevel(levelId);

        // Fast path: open immediately if level already exists locally.
        if (wasDownloaded && tryOpenLevelPage(levelId)) {
            auto* level = getBestLevel(manager, levelId);
            if (Mod::get()->getSettingValue<bool>("debug-logs")) {
                log::debug("[DashDiceBridge] Opened level {} immediately from cache", levelId);
            }

            // Refresh in background only if creator metadata is currently missing.
            if (level && !hasCreatorMetadata(level)) {
                manager->downloadLevel(levelId, false, 0);
                if (Mod::get()->getSettingValue<bool>("debug-logs")) {
                    log::debug("[DashDiceBridge] Creator missing on cached level {}, refreshing in background", levelId);
                }
                scheduleOpenWhenDownloaded(levelId, true);
            }
            return;
        }

        // Uncached path: request download and open placeholder right away.
        manager->downloadLevel(levelId, false, 0);
        const bool openedPlaceholder = tryOpenUncachedLevelInfoScene(levelId);

        if (Mod::get()->getSettingValue<bool>("debug-logs")) {
            if (openedPlaceholder) {
                log::debug("[DashDiceBridge] Opened placeholder for level {} while downloading", levelId);
            } else {
                log::debug("[DashDiceBridge] Download requested for level {}; waiting to open", levelId);
            }
        }

        scheduleOpenWhenDownloaded(levelId, false);
    });
}
} // namespace

namespace dashdice {
namespace {
constexpr int kDefaultPort = 47653;
constexpr int64_t kTimestampSkewMs = 45000;
constexpr int64_t kNonceTtlMs = 180000;

struct HttpRequest {
    std::string method;
    std::string path;
    std::unordered_map<std::string, std::string> headers;
    std::string body;
};

struct HttpResponse {
    int status = 200;
    std::string reason = "OK";
    matjson::Value body = matjson::makeObject({ { "ok", true } });
    std::string corsOrigin;
    bool includeCors = false;
    bool includePrivateNetworkHeader = false;
};

class BridgeServerImpl {
public:
    void onMenuReady() {
        if (!isEnabled()) {
            this->stop();
            return;
        }

        int configuredPort = Mod::get()->getSettingValue<int>("bridge-port");
        if (configuredPort < 1024 || configuredPort > 65535) {
            configuredPort = kDefaultPort;
        }

        std::string configuredOrigins = Mod::get()->getSettingValue<std::string>("bridge-allowed-origins");
        if (configuredOrigins.empty()) {
            configuredOrigins = "https://dash.motioncore.xyz";
        }

        bool needsRestart = false;
        {
            std::lock_guard<std::mutex> lock(m_stateMutex);
            if (!m_running.load()) {
                needsRestart = true;
            } else if (configuredPort != m_port || configuredOrigins != m_allowedOriginsRaw) {
                needsRestart = true;
            }

            m_port = configuredPort;
            m_allowedOriginsRaw = configuredOrigins;
            m_allowedOrigins.clear();
            for (auto const& origin : splitByComma(configuredOrigins)) {
                m_allowedOrigins.insert(origin);
            }
        }

        if (needsRestart) {
            this->stop();
            this->start();
        }
    }

    void start() {
        if (m_running.load()) {
            return;
        }
        if (m_thread.joinable()) {
            m_thread.join();
        }
        if (m_running.exchange(true)) {
            return;
        }

        {
            std::lock_guard<std::mutex> lock(m_stateMutex);
            m_sessionToken = randomHexToken(18);
            m_seenNonces.clear();
        }

        m_thread = std::thread([this]() { this->run(); });
    }

    void stop() {
        if (!m_running.exchange(false)) {
            if (m_thread.joinable()) {
                m_thread.join();
            }
            return;
        }

#ifdef GEODE_IS_WINDOWS
        SOCKET socketToClose = INVALID_SOCKET;
        {
            std::lock_guard<std::mutex> lock(m_socketMutex);
            socketToClose = m_listenSocket;
            m_listenSocket = INVALID_SOCKET;
        }
        if (socketToClose != INVALID_SOCKET) {
            shutdown(socketToClose, 2);
            closesocket(socketToClose);
        }
#endif

        if (m_thread.joinable()) {
            m_thread.join();
        }
    }

    ~BridgeServerImpl() {
        this->stop();
    }

private:
    bool isEnabled() const {
        return Mod::get()->getSettingValue<bool>("enable-open-level-bridge");
    }

    bool isDebugEnabled() const {
        return Mod::get()->getSettingValue<bool>("debug-logs");
    }

    bool isOriginAllowed(std::string const& origin) const {
        if (origin.empty()) return false;
        auto normalized = toLower(trim(origin));
        if (isLocalOrigin(normalized)) {
            return true;
        }
        std::lock_guard<std::mutex> lock(m_stateMutex);
        return m_allowedOrigins.count(normalized) != 0;
    }

    std::string resolveOriginForCors(HttpRequest const& request) const {
        auto it = request.headers.find("origin");
        if (it != request.headers.end()) {
            auto origin = toLower(trim(it->second));
            if (this->isOriginAllowed(origin)) return origin;
            return "";
        }

        auto refererIt = request.headers.find("referer");
        if (refererIt != request.headers.end()) {
            auto fromReferer = extractOriginFromReferer(refererIt->second);
            if (this->isOriginAllowed(fromReferer)) return fromReferer;
        }

        return "";
    }

    bool consumeNonce(std::string const& nonce, int64_t nowMs) {
        std::lock_guard<std::mutex> lock(m_stateMutex);

        for (auto it = m_seenNonces.begin(); it != m_seenNonces.end();) {
            if (nowMs - it->second > kNonceTtlMs) {
                it = m_seenNonces.erase(it);
            } else {
                ++it;
            }
        }

        if (m_seenNonces.count(nonce) != 0) {
            return false;
        }
        m_seenNonces.emplace(nonce, nowMs);
        return true;
    }

    std::string token() const {
        std::lock_guard<std::mutex> lock(m_stateMutex);
        return m_sessionToken;
    }

    int port() const {
        std::lock_guard<std::mutex> lock(m_stateMutex);
        return m_port;
    }

#ifdef GEODE_IS_WINDOWS
    static bool readRequest(SOCKET client, HttpRequest& out) {
        std::string raw;
        raw.reserve(4096);

        char buffer[4096];
        size_t headerEnd = std::string::npos;

        while (headerEnd == std::string::npos && raw.size() < 65536) {
            const int read = recv(client, buffer, static_cast<int>(sizeof(buffer)), 0);
            if (read <= 0) {
                return false;
            }
            raw.append(buffer, static_cast<size_t>(read));
            headerEnd = raw.find("\r\n\r\n");
        }

        if (headerEnd == std::string::npos) {
            return false;
        }

        std::string headerPart = raw.substr(0, headerEnd);
        std::stringstream headerStream(headerPart);
        std::string requestLine;
        if (!std::getline(headerStream, requestLine)) {
            return false;
        }
        if (!requestLine.empty() && requestLine.back() == '\r') {
            requestLine.pop_back();
        }

        std::stringstream requestLineStream(requestLine);
        std::string version;
        if (!(requestLineStream >> out.method >> out.path >> version)) {
            return false;
        }
        out.method = toLower(trim(out.method));

        std::string line;
        while (std::getline(headerStream, line)) {
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }
            auto sep = line.find(':');
            if (sep == std::string::npos) continue;
            auto key = toLower(trim(line.substr(0, sep)));
            auto value = trim(line.substr(sep + 1));
            out.headers[key] = value;
        }

        size_t contentLength = 0;
        if (auto it = out.headers.find("content-length"); it != out.headers.end()) {
            if (auto parsed = parseInt64(trim(it->second)); parsed && *parsed >= 0) {
                contentLength = static_cast<size_t>(*parsed);
            }
        }

        const size_t bodyStart = headerEnd + 4;
        while (raw.size() < bodyStart + contentLength) {
            const int read = recv(client, buffer, static_cast<int>(sizeof(buffer)), 0);
            if (read <= 0) {
                return false;
            }
            raw.append(buffer, static_cast<size_t>(read));
        }

        out.body = raw.substr(bodyStart, contentLength);
        return true;
    }

    static void sendResponse(SOCKET client, HttpResponse const& response) {
        const std::string payload = response.body.dump(matjson::NO_INDENTATION);

        std::ostringstream ss;
        ss << "HTTP/1.1 " << response.status << ' ' << response.reason << "\r\n";
        ss << "Content-Type: application/json; charset=utf-8\r\n";
        ss << "Content-Length: " << payload.size() << "\r\n";
        ss << "Connection: close\r\n";
        if (response.includeCors && !response.corsOrigin.empty()) {
            ss << "Access-Control-Allow-Origin: " << response.corsOrigin << "\r\n";
            ss << "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n";
            ss << "Access-Control-Allow-Headers: Content-Type, X-DashDice-Bridge-Token\r\n";
            ss << "Vary: Origin\r\n";
        }
        if (response.includePrivateNetworkHeader) {
            ss << "Access-Control-Allow-Private-Network: true\r\n";
        }
        ss << "\r\n" << payload;

        const std::string wire = ss.str();
        size_t offset = 0;
        while (offset < wire.size()) {
            int sent = send(client, wire.data() + offset, static_cast<int>(wire.size() - offset), 0);
            if (sent <= 0) {
                break;
            }
            offset += static_cast<size_t>(sent);
        }
    }

    HttpResponse makeJsonError(
        int status,
        std::string reason,
        std::string code,
        std::string message,
        std::string corsOrigin,
        bool includePrivateNetworkHeader = false
    ) const {
        HttpResponse response;
        response.status = status;
        response.reason = std::move(reason);
        response.body = matjson::makeObject({
            { "ok", false },
            { "code", code },
            { "message", message },
        });
        response.corsOrigin = std::move(corsOrigin);
        response.includeCors = !response.corsOrigin.empty();
        response.includePrivateNetworkHeader = includePrivateNetworkHeader;
        return response;
    }

    HttpResponse handle(HttpRequest const& request) {
        auto corsOrigin = this->resolveOriginForCors(request);
        const bool hasAllowedOrigin = !corsOrigin.empty();
        const bool privateNetworkRequested =
            request.headers.find("access-control-request-private-network") != request.headers.end();

        if (request.method == "options") {
            if (!hasAllowedOrigin) {
                return makeJsonError(
                    403,
                    "Forbidden",
                    "forbidden_origin",
                    "Origin is not allowed by DashDice bridge settings.",
                    "",
                    privateNetworkRequested
                );
            }

            HttpResponse response;
            response.status = 200;
            response.reason = "OK";
            response.body = matjson::makeObject({
                { "ok", true },
            });
            response.corsOrigin = corsOrigin;
            response.includeCors = true;
            response.includePrivateNetworkHeader = privateNetworkRequested;
            return response;
        }

        if (!hasAllowedOrigin) {
            return makeJsonError(
                403,
                "Forbidden",
                "forbidden_origin",
                "Origin is not allowed by DashDice bridge settings.",
                "",
                privateNetworkRequested
            );
        }

        std::string pathOnly = request.path;
        if (auto q = pathOnly.find('?'); q != std::string::npos) {
            pathOnly = pathOnly.substr(0, q);
        }

        if (request.method == "get" && pathOnly == "/health") {
            HttpResponse response;
            response.status = 200;
            response.reason = "OK";
            response.body = matjson::makeObject({
                { "ok", true },
                { "bridge", "dashdice.progress_sync" },
                { "port", this->port() },
                { "token", this->token() },
                { "time", fmt::format("{}", nowUnixMs()) },
            });
            response.corsOrigin = corsOrigin;
            response.includeCors = true;
            response.includePrivateNetworkHeader = privateNetworkRequested;
            return response;
        }

        if (request.method == "post" && pathOnly == "/open-level") {
            auto tokenHeaderIt = request.headers.find("x-dashdice-bridge-token");
            if (tokenHeaderIt == request.headers.end() || trim(tokenHeaderIt->second) != this->token()) {
                return makeJsonError(
                    401,
                    "Unauthorized",
                    "invalid_token",
                    "Bridge token is missing or invalid. Refresh the page and try again.",
                    corsOrigin,
                    privateNetworkRequested
                );
            }

            auto parsedPayload = matjson::parse(request.body);
            if (parsedPayload.isErr()) {
                return makeJsonError(
                    400,
                    "Bad Request",
                    "invalid_json",
                    "Invalid JSON body.",
                    corsOrigin,
                    privateNetworkRequested
                );
            }
            auto payload = parsedPayload.unwrap();

            if (!payload.isObject()) {
                return makeJsonError(
                    400,
                    "Bad Request",
                    "invalid_payload",
                    "Expected JSON object payload.",
                    corsOrigin,
                    privateNetworkRequested
                );
            }

            auto nonceRes = payload["nonce"].asString();
            auto tsRes = payload["ts"].asInt();
            if (nonceRes.isErr() || tsRes.isErr()) {
                return makeJsonError(
                    400,
                    "Bad Request",
                    "missing_security_fields",
                    "Payload must include nonce and ts.",
                    corsOrigin,
                    privateNetworkRequested
                );
            }

            const std::string nonce = nonceRes.unwrap();
            if (!isValidNonce(nonce)) {
                return makeJsonError(
                    400,
                    "Bad Request",
                    "invalid_nonce",
                    "Nonce format is invalid.",
                    corsOrigin,
                    privateNetworkRequested
                );
            }

            const int64_t requestTs = tsRes.unwrap();
            const int64_t nowMs = nowUnixMs();
            if (std::llabs(nowMs - requestTs) > kTimestampSkewMs) {
                return makeJsonError(
                    422,
                    "Unprocessable Content",
                    "timestamp_out_of_window",
                    "Request timestamp is too old/new. Refresh and try again.",
                    corsOrigin,
                    privateNetworkRequested
                );
            }

            if (!this->consumeNonce(nonce, nowMs)) {
                return makeJsonError(
                    409,
                    "Conflict",
                    "nonce_replay",
                    "Request nonce was already used.",
                    corsOrigin,
                    privateNetworkRequested
                );
            }

            int64_t levelId = 0;
            if (payload["levelId"].isNumber()) {
                auto levelRes = payload["levelId"].asInt();
                if (levelRes.isErr()) {
                    return makeJsonError(
                        400,
                        "Bad Request",
                        "invalid_level_id",
                        "levelId must be a positive integer.",
                        corsOrigin,
                        privateNetworkRequested
                    );
                }
                levelId = levelRes.unwrap();
            } else if (payload["levelId"].isString()) {
                auto levelStrRes = payload["levelId"].asString();
                if (levelStrRes.isErr()) {
                    return makeJsonError(
                        400,
                        "Bad Request",
                        "invalid_level_id",
                        "levelId must be a positive integer.",
                        corsOrigin,
                        privateNetworkRequested
                    );
                }
                auto parsed = parseInt64(trim(levelStrRes.unwrap()));
                if (!parsed.has_value()) {
                    return makeJsonError(
                        400,
                        "Bad Request",
                        "invalid_level_id",
                        "levelId must be a positive integer.",
                        corsOrigin,
                        privateNetworkRequested
                    );
                }
                levelId = parsed.value();
            } else {
                return makeJsonError(
                    400,
                    "Bad Request",
                    "invalid_level_id",
                    "levelId must be a positive integer.",
                    corsOrigin,
                    privateNetworkRequested
                );
            }

            if (levelId <= 0 || levelId > 2000000000LL) {
                return makeJsonError(
                    400,
                    "Bad Request",
                    "invalid_level_id",
                    "levelId is out of allowed range.",
                    corsOrigin,
                    privateNetworkRequested
                );
            }

            queueOpenLevel(static_cast<int>(levelId));

            HttpResponse response;
            response.status = 200;
            response.reason = "OK";
            response.body = matjson::makeObject({
                { "ok", true },
                { "accepted", true },
                { "message", "Level open request queued in Geometry Dash." },
            });
            response.corsOrigin = corsOrigin;
            response.includeCors = true;
            response.includePrivateNetworkHeader = privateNetworkRequested;
            return response;
        }

        return makeJsonError(
            404,
            "Not Found",
            "not_found",
            "Unknown bridge endpoint.",
            corsOrigin,
            privateNetworkRequested
        );
    }

    void run() {
        WSADATA wsaData {};
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            m_running.store(false);
            log::warn("[DashDiceBridge] WSAStartup failed");
            return;
        }

        SOCKET listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listenSocket == INVALID_SOCKET) {
            WSACleanup();
            m_running.store(false);
            log::warn("[DashDiceBridge] Failed to create listen socket");
            return;
        }

        {
            std::lock_guard<std::mutex> lock(m_socketMutex);
            m_listenSocket = listenSocket;
        }

        u_long mode = 1;
        ioctlsocket(listenSocket, FIONBIO, &mode);

        sockaddr_in addr {};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(static_cast<u_short>(this->port()));
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

        if (bind(listenSocket, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
            if (this->isDebugEnabled()) {
                log::warn("[DashDiceBridge] Failed to bind to 127.0.0.1:{}", this->port());
            }
            closesocket(listenSocket);
            WSACleanup();
            {
                std::lock_guard<std::mutex> lock(m_socketMutex);
                m_listenSocket = INVALID_SOCKET;
            }
            m_running.store(false);
            return;
        }

        if (listen(listenSocket, SOMAXCONN) == SOCKET_ERROR) {
            closesocket(listenSocket);
            WSACleanup();
            {
                std::lock_guard<std::mutex> lock(m_socketMutex);
                m_listenSocket = INVALID_SOCKET;
            }
            m_running.store(false);
            return;
        }

        if (this->isDebugEnabled()) {
            log::debug("[DashDiceBridge] Listening on 127.0.0.1:{}", this->port());
        }

        while (m_running.load()) {
            fd_set readSet;
            FD_ZERO(&readSet);
            FD_SET(listenSocket, &readSet);
            timeval timeout { 0, 250000 };

            int ready = select(0, &readSet, nullptr, nullptr, &timeout);
            if (ready <= 0 || !FD_ISSET(listenSocket, &readSet)) {
                continue;
            }

            SOCKET client = accept(listenSocket, nullptr, nullptr);
            if (client == INVALID_SOCKET) {
                continue;
            }

            u_long clientMode = 0;
            ioctlsocket(client, FIONBIO, &clientMode);

            HttpRequest request;
            if (!readRequest(client, request)) {
                closesocket(client);
                continue;
            }

            auto response = this->handle(request);
            sendResponse(client, response);
            closesocket(client);
        }

        closesocket(listenSocket);
        {
            std::lock_guard<std::mutex> lock(m_socketMutex);
            m_listenSocket = INVALID_SOCKET;
        }
        WSACleanup();
    }
#else
    void run() {
        m_running.store(false);
    }
#endif

private:
    std::atomic<bool> m_running { false };
    mutable std::mutex m_stateMutex;
    std::thread m_thread;

#ifdef GEODE_IS_WINDOWS
    mutable std::mutex m_socketMutex;
    SOCKET m_listenSocket { INVALID_SOCKET };
#endif

    int m_port { kDefaultPort };
    std::string m_allowedOriginsRaw { "https://dash.motioncore.xyz" };
    std::unordered_set<std::string> m_allowedOrigins;
    std::unordered_map<std::string, int64_t> m_seenNonces;
    std::string m_sessionToken;
};
} // namespace

BridgeServer& BridgeServer::get() {
    static BridgeServer instance;
    return instance;
}

BridgeServer::~BridgeServer() = default;

void BridgeServer::onMenuReady() {
    static BridgeServerImpl impl;
    impl.onMenuReady();
}
} // namespace dashdice
