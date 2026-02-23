#include "SyncManager.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <optional>
#include <random>
#include <regex>
#include <string>
#include <thread>

#include <fmt/core.h>
#include <Geode/Result.hpp>
#include <Geode/binding/GJAccountManager.hpp>
#include <Geode/binding/GameManager.hpp>
#include <Geode/binding/GameLevelManager.hpp>
#include <Geode/loader/Log.hpp>
#include <Geode/loader/Loader.hpp>
#include <Geode/loader/Mod.hpp>
#include <Geode/ui/Popup.hpp>
#include <Geode/utils/async.hpp>
#include <Geode/utils/web.hpp>

#include "../bridge/LocalBridge.hpp"

using namespace geode::prelude;

namespace {
constexpr bool kDefaultEnableSync = true;
constexpr bool kDefaultDebugLogs = true;
constexpr int kDefaultRequestTimeout = 12;
constexpr char const* kDefaultSyncEndpoint = "https://dash.motioncore.xyz/api/sync/progress";

bool loadMirroredBool(char const* settingKey, char const* mirrorKey, bool defaultValue) {
    auto* mod = Mod::get();
    if (!mod) return defaultValue;

    bool current = mod->getSettingValue<bool>(settingKey);
    const bool hasMirror = mod->hasSavedValue(mirrorKey);
    const bool mirrored = mod->getSavedValue<bool>(mirrorKey, defaultValue);

    if (hasMirror && current == defaultValue && mirrored != current) {
        mod->setSettingValue(settingKey, mirrored);
        current = mirrored;
    }

    if (!hasMirror || mirrored != current) {
        mod->setSavedValue(mirrorKey, current);
    }

    return current;
}

int loadMirroredInt(char const* settingKey, char const* mirrorKey, int defaultValue, int minValue) {
    auto* mod = Mod::get();
    if (!mod) return defaultValue;

    int current = mod->getSettingValue<int>(settingKey);
    if (current < minValue) current = defaultValue;

    const bool hasMirror = mod->hasSavedValue(mirrorKey);
    int mirrored = mod->getSavedValue<int>(mirrorKey, defaultValue);
    if (mirrored < minValue) mirrored = defaultValue;

    if (hasMirror && current == defaultValue && mirrored != current) {
        mod->setSettingValue(settingKey, mirrored);
        current = mirrored;
    }

    if (!hasMirror || mirrored != current) {
        mod->setSavedValue(mirrorKey, current);
    }

    return current;
}

std::string loadMirroredString(char const* settingKey, char const* mirrorKey, char const* defaultValue) {
    auto* mod = Mod::get();
    if (!mod) return defaultValue;

    std::string current = mod->getSettingValue<std::string>(settingKey);
    const bool hasMirror = mod->hasSavedValue(mirrorKey);
    const std::string mirrored = mod->getSavedValue<std::string>(mirrorKey, "");
    const bool currentIsDefaultLike = current.empty() || current == defaultValue;

    if (hasMirror && !mirrored.empty() && currentIsDefaultLike && mirrored != current) {
        mod->setSettingValue(settingKey, mirrored);
        current = mirrored;
    }

    if (!current.empty() && (!hasMirror || mirrored != current)) {
        mod->setSavedValue(mirrorKey, current);
    }

    if (current.empty()) {
        return defaultValue;
    }
    return current;
}

std::string makeEventId() {
    static std::mt19937_64 rng { std::random_device {}() };
    static std::uniform_int_distribution<std::uint64_t> dist;

    const auto nowMs =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count();

    return fmt::format("{}-{:016x}", nowMs, dist(rng));
}

std::int64_t nowUnixMs() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
        .count();
}

int clampPercent(int value) {
    return std::clamp(value, 0, 100);
}

matjson::Value popFront(const matjson::Value& arr) {
    matjson::Value out = matjson::Value::array();
    bool skippedFirst = false;
    for (const auto& item : arr) {
        if (!skippedFirst) {
            skippedFirst = true;
            continue;
        }
        out.push(item);
    }
    return out;
}

std::string pingUrlFromProgressUrl(const std::string& progressUrl) {
    constexpr const char* suffix = "/progress";
    const auto suffixLen = std::char_traits<char>::length(suffix);
    if (progressUrl.size() >= suffixLen &&
        progressUrl.compare(progressUrl.size() - suffixLen, suffixLen, suffix) == 0) {
        return progressUrl.substr(0, progressUrl.size() - suffixLen) + "/ping";
    }
    return progressUrl;
}

std::string commandsUrlFromProgressUrl(const std::string& progressUrl) {
    constexpr const char* suffix = "/progress";
    const auto suffixLen = std::char_traits<char>::length(suffix);
    if (progressUrl.size() >= suffixLen &&
        progressUrl.compare(progressUrl.size() - suffixLen, suffixLen, suffix) == 0) {
        return progressUrl.substr(0, progressUrl.size() - suffixLen) + "/commands";
    }
    return progressUrl;
}

std::optional<std::string> extractJsonString(std::string const& body, std::string const& key) {
    std::regex re("\"" + key + "\"\\s*:\\s*\"([^\"]*)\"");
    std::smatch match;
    if (!std::regex_search(body, match, re)) return std::nullopt;
    return match[1].str();
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
} // namespace

namespace dashdice {
SyncManager& SyncManager::get() {
    static SyncManager instance;
    return instance;
}

bool SyncManager::isEnabled() const {
    return loadMirroredBool("enable-sync", "persist-setting-enable-sync", kDefaultEnableSync);
}

bool SyncManager::isDebugEnabled() const {
    return loadMirroredBool("debug-logs", "persist-setting-debug-logs", kDefaultDebugLogs);
}

std::string SyncManager::serverUrl() const {
    return loadMirroredString("server-url", "persist-setting-server-url", kDefaultSyncEndpoint);
}

std::string SyncManager::apiKey() const {
    return loadMirroredString("api-key", "persist-setting-api-key", "");
}

int SyncManager::timeoutSeconds() const {
    return loadMirroredInt("request-timeout", "persist-setting-request-timeout", kDefaultRequestTimeout, 3);
}

matjson::Value SyncManager::loadQueue() const {
    matjson::Value queue = Mod::get()->getSavedValue<matjson::Value>("pending-progress-events", matjson::Value::array());
    if (!queue.isArray()) {
        return matjson::Value::array();
    }
    return queue;
}

void SyncManager::saveQueue(const matjson::Value& queue) const {
    Mod::get()->setSavedValue("pending-progress-events", queue.isArray() ? queue : matjson::Value::array());
}

void SyncManager::appendQueue(const matjson::Value& payload) {
    matjson::Value queue = this->loadQueue();
    queue.push(payload);
    this->saveQueue(queue);
}

SyncManager::ProfileSnapshot SyncManager::collectProfileSnapshot() {
    ProfileSnapshot snapshot;

    auto* accountMgr = GJAccountManager::sharedState();
    auto* gameMgr = GameManager::sharedState();
    auto* levelMgr = GameLevelManager::sharedState();

    snapshot.accountId = accountMgr ? accountMgr->m_accountID : 0;
    snapshot.hasAccount = snapshot.accountId > 0;
    snapshot.username = (accountMgr && !accountMgr->m_username.empty()) ? accountMgr->m_username : "";

    if (gameMgr != nullptr) {
        snapshot.playerName = !gameMgr->m_playerName.empty() ? gameMgr->m_playerName : "";
        snapshot.userId = static_cast<int>(gameMgr->m_playerUserID.value());

        snapshot.iconCube = gameMgr->getPlayerFrame();
        snapshot.iconShip = gameMgr->getPlayerShip();
        snapshot.iconBall = gameMgr->getPlayerBall();
        snapshot.iconUfo = gameMgr->getPlayerBird();
        snapshot.iconWave = gameMgr->getPlayerDart();
        snapshot.iconRobot = gameMgr->getPlayerRobot();
        snapshot.iconSpider = gameMgr->getPlayerSpider();
        snapshot.iconSwing = gameMgr->getPlayerSwing();
        snapshot.iconJetpack = gameMgr->getPlayerJetpack();
        snapshot.color1 = gameMgr->getPlayerColor();
        snapshot.color2 = gameMgr->getPlayerColor2();
        snapshot.glowEnabled = gameMgr->getPlayerGlow() ? 1 : 0;
    }

    if (levelMgr != nullptr && snapshot.accountId > 0) {
        if (auto* score = levelMgr->userInfoForAccountID(snapshot.accountId); score != nullptr) {
            snapshot.hasStats = true;
            snapshot.stars = score->m_stars;
            snapshot.moons = score->m_moons;
            snapshot.demons = score->m_demons;
            snapshot.userCoins = score->m_userCoins;
            snapshot.secretCoins = score->m_secretCoins;

            if (!score->m_userName.empty()) {
                snapshot.username = score->m_userName;
            }
            if (snapshot.userId <= 0) {
                snapshot.userId = score->m_userID;
            }
        } else {
            this->requestProfileSnapshotIfNeeded(snapshot.accountId, snapshot.userId);
        }
    }

    return snapshot;
}

void SyncManager::requestProfileSnapshotIfNeeded(int accountId, int userId) {
    auto* levelMgr = GameLevelManager::sharedState();
    if (levelMgr == nullptr || accountId <= 0) {
        return;
    }

    const auto nowMs = nowUnixMs();
    if (nowMs - m_lastProfileRequestMs < 30'000) {
        return;
    }
    m_lastProfileRequestMs = nowMs;

    if (userId > 0) {
        levelMgr->getGJUserInfo(userId);
    }
    levelMgr->getGJUserInfo(accountId);

    if (this->isDebugEnabled()) {
        log::debug(
            "[ProgressSync] Requested profile snapshot (accountId={}, userId={})",
            accountId,
            userId
        );
    }
}

void SyncManager::enqueueFromLevel(GJGameLevel* level, bool levelCompleted) {
    if (!this->isEnabled() || level == nullptr) {
        return;
    }

    const int levelId = static_cast<int>(level->m_levelID.value());
    if (levelId <= 0) {
        return;
    }

    const int normal = clampPercent(static_cast<int>(level->m_normalPercent.value()));
    const int practice = clampPercent(level->m_practicePercent);
    const int attempts = std::max(0, static_cast<int>(level->m_attempts.value()));
    const auto snapshot = std::tuple(normal, practice, attempts);
    const auto profile = this->collectProfileSnapshot();

    const auto found = m_lastSeenByLevel.find(levelId);
    if (found != m_lastSeenByLevel.end() && found->second == snapshot) {
        return;
    }
    m_lastSeenByLevel[levelId] = snapshot;

    matjson::Value payload = matjson::makeObject({
        { "eventId", makeEventId() },
        { "levelId", levelId },
        { "normal", normal },
        { "practice", practice },
        { "attempts", attempts },
        { "clientTs", fmt::format("{}", nowUnixMs()) },
        { "source", levelCompleted ? "levelComplete" : "onQuit" },
        { "gdHasAccount", profile.hasAccount },
        { "gdAccountId", profile.accountId },
        { "gdUserId", profile.userId },
        { "gdUsername", profile.username },
        { "gdPlayerName", profile.playerName },
        { "gdStatsAvailable", profile.hasStats },
        { "gdStars", profile.stars },
        { "gdMoons", profile.moons },
        { "gdDemons", profile.demons },
        { "gdUserCoins", profile.userCoins },
        { "gdSecretCoins", profile.secretCoins },
        { "gdIconCube", profile.iconCube },
        { "gdIconShip", profile.iconShip },
        { "gdIconBall", profile.iconBall },
        { "gdIconUfo", profile.iconUfo },
        { "gdIconWave", profile.iconWave },
        { "gdIconRobot", profile.iconRobot },
        { "gdIconSpider", profile.iconSpider },
        { "gdIconSwing", profile.iconSwing },
        { "gdIconJetpack", profile.iconJetpack },
        { "gdColor1", profile.color1 },
        { "gdColor2", profile.color2 },
        { "gdGlowEnabled", profile.glowEnabled },
    });

    this->appendQueue(payload);
    this->runFlush();
}

void SyncManager::onMenuReady() {
    this->maybeWarnNoAccount();
    this->runPing();
    this->runFlush();
    this->runCommandPoll();
    this->ensureCommandPollLoop();
}

void SyncManager::onProfilePossiblyChanged() {
    if (!this->isEnabled()) {
        return;
    }

    const std::string url = this->serverUrl();
    const std::string key = this->apiKey();
    if (url.empty() || key.empty()) {
        return;
    }

    const auto profile = this->collectProfileSnapshot();
    const auto nowMs = nowUnixMs();
    const std::string signature = fmt::format(
        "{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
        profile.accountId,
        profile.userId,
        profile.iconCube,
        profile.iconShip,
        profile.iconBall,
        profile.iconUfo,
        profile.iconWave,
        profile.iconRobot,
        profile.iconSpider,
        profile.iconSwing,
        profile.iconJetpack,
        profile.color1,
        profile.color2,
        profile.glowEnabled,
        profile.username
    );

    const bool changed = signature != m_lastProfileSignature;
    const bool cooldownElapsed = (nowMs - m_lastProfilePingMs) >= 2'000;
    if (!changed && !cooldownElapsed) {
        return;
    }

    m_lastProfileSignature = signature;
    m_lastProfilePingMs = nowMs;
    if (this->isDebugEnabled()) {
        log::debug(
            "[ProgressSync] Profile change ping queued (changed={}, cooldownElapsed={}, accountId={}, cube={}, ship={}, ball={}, ufo={}, wave={}, robot={}, spider={}, swing={}, jetpack={}, c1={}, c2={}, glow={})",
            changed,
            cooldownElapsed,
            profile.accountId,
            profile.iconCube,
            profile.iconShip,
            profile.iconBall,
            profile.iconUfo,
            profile.iconWave,
            profile.iconRobot,
            profile.iconSpider,
            profile.iconSwing,
            profile.iconJetpack,
            profile.color1,
            profile.color2,
            profile.glowEnabled
        );
    }
    this->runPing();
}

void SyncManager::flushQueue() {
    this->runFlush();
}

void SyncManager::runFlush() {
    if (!this->isEnabled()) {
        return;
    }

    const std::string url = this->serverUrl();
    const std::string key = this->apiKey();
    if (url.empty() || key.empty()) {
        return;
    }

    if (m_flushing.exchange(true)) {
        return;
    }

    async::spawn(this->flushAsync(), [this](Result<> result) {
        m_flushing.store(false);
        if (GEODE_UNWRAP_IF_ERR(err, result)) {
            if (this->isDebugEnabled()) {
                log::warn("[ProgressSync] Flush failed: {}", err);
            }
            return;
        }

        if (this->isDebugEnabled()) {
            log::debug("[ProgressSync] Queue flush completed");
        }
    });
}

void SyncManager::runPing() {
    if (!this->isEnabled()) {
        return;
    }

    const std::string url = this->serverUrl();
    const std::string key = this->apiKey();
    if (url.empty() || key.empty()) {
        return;
    }

    if (m_pinging.exchange(true)) {
        return;
    }

    async::spawn(this->pingAsync(), [this](Result<> result) {
        m_pinging.store(false);
        if (GEODE_UNWRAP_IF_ERR(err, result)) {
            if (this->isDebugEnabled()) {
                log::warn("[ProgressSync] Ping failed: {}", err);
            }
            return;
        }

        if (this->isDebugEnabled()) {
            log::debug("[ProgressSync] Connection ping completed");
        }
    });
}

void SyncManager::runCommandPoll() {
    if (!this->isEnabled()) {
        return;
    }

    const std::string url = this->serverUrl();
    const std::string key = this->apiKey();
    if (url.empty() || key.empty()) {
        return;
    }

    if (m_pollingCommands.exchange(true)) {
        return;
    }

    async::spawn(this->pollCommandsAsync(), [this](Result<> result) {
        m_pollingCommands.store(false);
        if (GEODE_UNWRAP_IF_ERR(err, result)) {
            if (this->isDebugEnabled()) {
                log::warn("[ProgressSync] Command poll failed: {}", err);
            }
            return;
        }
    });
}

void SyncManager::ensureCommandPollLoop() {
    if (m_commandLoopStarted.exchange(true)) {
        return;
    }

    std::thread([this]() {
        while (m_commandLoopStarted.load()) {
            std::this_thread::sleep_for(std::chrono::seconds(2));
            if (!m_commandLoopStarted.load()) {
                break;
            }
            // Poll commands directly from the loop thread so remote opens still
            // get claimed while GD is backgrounded / main thread is throttled.
            this->runCommandPoll();
        }
    }).detach();
}

arc::Future<Result<>> SyncManager::pingAsync() {
    const auto profile = this->collectProfileSnapshot();

    matjson::Value payload = matjson::makeObject({
        { "clientTs", fmt::format("{}", nowUnixMs()) },
        { "source", "menuPing" },
        { "gdHasAccount", profile.hasAccount },
        { "gdAccountId", profile.accountId },
        { "gdUserId", profile.userId },
        { "gdUsername", profile.username },
        { "gdPlayerName", profile.playerName },
        { "gdStatsAvailable", profile.hasStats },
        { "gdStars", profile.stars },
        { "gdMoons", profile.moons },
        { "gdDemons", profile.demons },
        { "gdUserCoins", profile.userCoins },
        { "gdSecretCoins", profile.secretCoins },
        { "gdIconCube", profile.iconCube },
        { "gdIconShip", profile.iconShip },
        { "gdIconBall", profile.iconBall },
        { "gdIconUfo", profile.iconUfo },
        { "gdIconWave", profile.iconWave },
        { "gdIconRobot", profile.iconRobot },
        { "gdIconSpider", profile.iconSpider },
        { "gdIconSwing", profile.iconSwing },
        { "gdIconJetpack", profile.iconJetpack },
        { "gdColor1", profile.color1 },
        { "gdColor2", profile.color2 },
        { "gdGlowEnabled", profile.glowEnabled },
    });

    const std::string pingUrl = pingUrlFromProgressUrl(this->serverUrl());
    const std::string key = this->apiKey();

    const web::WebResponse pingResponse = co_await web::WebRequest()
                                          .timeout(std::chrono::seconds(this->timeoutSeconds()))
                                          .header("Authorization", fmt::format("Bearer {}", key))
                                          .header("Content-Type", "application/json")
                                          .bodyJSON(payload)
                                          .post(pingUrl);

    if (!pingResponse.ok()) {
        std::string pingBody;
        if (auto bodyRes = pingResponse.string(); bodyRes.isOk()) {
            pingBody = bodyRes.unwrap();
        }

        // Some deployments can have /ping out-of-sync while /progress auth is valid.
        // Verify against the actual progress endpoint before reporting invalid key.
        const web::WebResponse authCheck = co_await web::WebRequest()
                                               .timeout(std::chrono::seconds(this->timeoutSeconds()))
                                               .header("Authorization", fmt::format("Bearer {}", key))
                                               .get(this->serverUrl());
        if (authCheck.ok()) {
            if (this->isDebugEnabled()) {
                log::debug(
                    "[ProgressSync] Ping endpoint failed (HTTP {}), but progress auth-check succeeded",
                    pingResponse.code()
                );
            }
            co_return Ok();
        }

        std::string checkBody;
        if (auto bodyRes = authCheck.string(); bodyRes.isOk()) {
            checkBody = bodyRes.unwrap();
        }

        co_return Err(fmt::format(
            "HTTP {} while pinging sync{}{}; auth-check failed with HTTP {}{}{}",
            pingResponse.code(),
            pingBody.empty() ? "" : ": ",
            pingBody,
            authCheck.code(),
            checkBody.empty() ? "" : ": ",
            checkBody
        ));
    }

    co_return Ok();
}

arc::Future<Result<>> SyncManager::pollCommandsAsync() {
    const std::string commandsUrl = commandsUrlFromProgressUrl(this->serverUrl());
    const std::string key = this->apiKey();
    if (commandsUrl.empty() || key.empty()) {
        co_return Ok();
    }

    auto response = co_await web::WebRequest()
                        .timeout(std::chrono::seconds(this->timeoutSeconds()))
                        .header("Authorization", fmt::format("Bearer {}", key))
                        .get(commandsUrl);

    if (response.code() == 404) {
        co_return Ok();
    }
    if (!response.ok()) {
        std::string body;
        if (auto bodyRes = response.string(); bodyRes.isOk()) {
            body = bodyRes.unwrap();
        }
        co_return Err(fmt::format(
            "HTTP {} while polling commands{}{}",
            response.code(),
            body.empty() ? "" : ": ",
            body
        ));
    }

    std::string body;
    if (auto bodyRes = response.string(); bodyRes.isOk()) {
        body = bodyRes.unwrap();
    } else {
        co_return Err("Command poll response was not readable.");
    }

    if (body.find(R"("command":null)") != std::string::npos || body.find(R"("command": null)") != std::string::npos) {
        co_return Ok();
    }

    auto commandId = extractJsonString(body, "commandId").value_or("");
    auto claimToken = extractJsonString(body, "claimToken").value_or("");
    auto kind = extractJsonString(body, "kind").value_or("");
    auto levelId = extractJsonInt(body, "levelId").value_or(0);

    if (commandId.empty() || claimToken.empty()) {
        co_return Ok();
    }

    bool success = false;
    std::string result = "Unsupported command.";

    if (kind == "open_level" && levelId > 0) {
        LocalBridge::get().openLevelFromRemote(levelId);
        success = true;
        result = fmt::format("Opening level {}.", levelId);
        if (this->isDebugEnabled()) {
            log::debug("[ProgressSync] Received remote open command for level {}", levelId);
        }
    }

    matjson::Value ackPayload = matjson::makeObject({
        { "commandId", commandId },
        { "claimToken", claimToken },
        { "success", success },
        { "result", result },
    });

    auto ack = co_await web::WebRequest()
                   .timeout(std::chrono::seconds(this->timeoutSeconds()))
                   .header("Authorization", fmt::format("Bearer {}", key))
                   .header("Content-Type", "application/json")
                   .bodyJSON(ackPayload)
                   .post(commandsUrl);

    if (!ack.ok()) {
        std::string ackBody;
        if (auto bodyRes = ack.string(); bodyRes.isOk()) {
            ackBody = bodyRes.unwrap();
        }
        co_return Err(fmt::format(
            "HTTP {} while acknowledging command{}{}",
            ack.code(),
            ackBody.empty() ? "" : ": ",
            ackBody
        ));
    }

    co_return Ok();
}

arc::Future<Result<>> SyncManager::flushAsync() {
    while (true) {
        const matjson::Value queue = this->loadQueue();
        if (!queue.isArray() || queue.size() == 0) {
            break;
        }

        const matjson::Value first = queue[0];
        Result<matjson::Value> response = co_await this->postPayload(first);
        if (GEODE_UNWRAP_IF_ERR(err, response)) {
            co_return Err(err);
        }

        this->saveQueue(popFront(queue));
    }

    co_return Ok();
}

arc::Future<Result<matjson::Value>> SyncManager::postPayload(const matjson::Value& payload) {
    const std::string url = this->serverUrl();
    const std::string key = this->apiKey();
    if (url.empty()) {
        co_return Err("Missing 'server-url' setting");
    }
    if (key.empty()) {
        co_return Err("Missing 'api-key' setting");
    }

    const web::WebResponse response = co_await web::WebRequest()
                                          .timeout(std::chrono::seconds(this->timeoutSeconds()))
                                          .header("Authorization", fmt::format("Bearer {}", key))
                                          .header("Content-Type", "application/json")
                                          .bodyJSON(payload)
                                          .post(url);

    if (!response.ok()) {
        std::string body;
        if (auto bodyRes = response.string(); bodyRes.isOk()) {
            body = bodyRes.unwrap();
        }

        co_return Err(fmt::format(
            "HTTP {} while syncing progress{}{}",
            response.code(),
            body.empty() ? "" : ": ",
            body
        ));
    }

    Result<matjson::Value> json = response.json();
    if (GEODE_UNWRAP_IF_ERR(err, json)) {
        co_return Err(fmt::format("Server returned non-JSON response: {}", err));
    }

    co_return Ok(json.unwrap());
}

void SyncManager::maybeWarnNoAccount() {
    if (m_warnedNoAccount || !this->isEnabled()) {
        return;
    }

    auto* accountMgr = GJAccountManager::sharedState();
    if (accountMgr && accountMgr->m_accountID > 0) {
        return;
    }

    m_warnedNoAccount = true;
    geode::createQuickPopup(
        "Progress Sync Notice",
        "You are not logged into a Geometry Dash account. "
        "We cannot guarantee your sync data will be safely recoverable if anything changes.\n"
        "For best reliability, log into a GD account.",
        "OK",
        nullptr,
        [](FLAlertLayer*, bool) {},
        true
    );
}
} // namespace dashdice
