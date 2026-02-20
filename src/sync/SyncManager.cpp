#include "SyncManager.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <random>
#include <string>

#include <fmt/core.h>
#include <Geode/Result.hpp>
#include <Geode/binding/GJAccountManager.hpp>
#include <Geode/binding/GameManager.hpp>
#include <Geode/loader/Log.hpp>
#include <Geode/loader/Mod.hpp>
#include <Geode/ui/Popup.hpp>
#include <Geode/utils/async.hpp>
#include <Geode/utils/web.hpp>

using namespace geode::prelude;

namespace {
std::string makeEventId() {
    static std::mt19937_64 rng { std::random_device {}() };
    static std::uniform_int_distribution<std::uint64_t> dist;

    const auto nowMs =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count();

    return fmt::format("{}-{:016x}", nowMs, dist(rng));
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
} // namespace

namespace dashdice {
SyncManager& SyncManager::get() {
    static SyncManager instance;
    return instance;
}

bool SyncManager::isEnabled() const {
    return Mod::get()->getSettingValue<bool>("enable-sync");
}

bool SyncManager::isDebugEnabled() const {
    return Mod::get()->getSettingValue<bool>("debug-logs");
}

std::string SyncManager::serverUrl() const {
    return Mod::get()->getSettingValue<std::string>("server-url");
}

std::string SyncManager::apiKey() const {
    return Mod::get()->getSettingValue<std::string>("api-key");
}

int SyncManager::timeoutSeconds() const {
    int timeout = Mod::get()->getSettingValue<int>("request-timeout");
    if (timeout < 3) timeout = 3;
    return timeout;
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
    auto* accountMgr = GJAccountManager::sharedState();
    auto* gameMgr = GameManager::sharedState();
    const int gdAccountId = accountMgr ? accountMgr->m_accountID : 0;
    const bool gdHasAccount = gdAccountId > 0;
    const std::string gdUsername =
        accountMgr && !accountMgr->m_username.empty() ? accountMgr->m_username : "";
    const std::string gdPlayerName =
        gameMgr && !gameMgr->m_playerName.empty() ? gameMgr->m_playerName : "";

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
        { "clientTs", fmt::format("{}", std::chrono::duration_cast<std::chrono::milliseconds>(
                                            std::chrono::system_clock::now().time_since_epoch())
                                            .count()) },
        { "source", levelCompleted ? "levelComplete" : "onQuit" },
        { "gdHasAccount", gdHasAccount },
        { "gdAccountId", gdAccountId },
        { "gdUsername", gdUsername },
        { "gdPlayerName", gdPlayerName },
    });

    this->appendQueue(payload);
    this->runFlush();
}

void SyncManager::onMenuReady() {
    this->maybeWarnNoAccount();
    this->runPing();
    this->runFlush();
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

arc::Future<Result<>> SyncManager::pingAsync() {
    auto* accountMgr = GJAccountManager::sharedState();
    auto* gameMgr = GameManager::sharedState();
    const int gdAccountId = accountMgr ? accountMgr->m_accountID : 0;
    const bool gdHasAccount = gdAccountId > 0;
    const std::string gdUsername =
        accountMgr && !accountMgr->m_username.empty() ? accountMgr->m_username : "";
    const std::string gdPlayerName =
        gameMgr && !gameMgr->m_playerName.empty() ? gameMgr->m_playerName : "";

    matjson::Value payload = matjson::makeObject({
        { "clientTs", fmt::format("{}", std::chrono::duration_cast<std::chrono::milliseconds>(
                                            std::chrono::system_clock::now().time_since_epoch())
                                            .count()) },
        { "source", "menuPing" },
        { "gdHasAccount", gdHasAccount },
        { "gdAccountId", gdAccountId },
        { "gdUsername", gdUsername },
        { "gdPlayerName", gdPlayerName },
    });

    const std::string pingUrl = pingUrlFromProgressUrl(this->serverUrl());
    const std::string key = this->apiKey();

    const web::WebResponse response = co_await web::WebRequest()
                                          .timeout(std::chrono::seconds(this->timeoutSeconds()))
                                          .header("Authorization", fmt::format("Bearer {}", key))
                                          .header("Content-Type", "application/json")
                                          .bodyJSON(payload)
                                          .post(pingUrl);

    if (!response.ok()) {
        std::string body;
        if (auto bodyRes = response.string(); bodyRes.isOk()) {
            body = bodyRes.unwrap();
        }

        co_return Err(fmt::format(
            "HTTP {} while pinging sync{}{}",
            response.code(),
            body.empty() ? "" : ": ",
            body
        ));
    }

    Result<matjson::Value> json = response.json();
    if (GEODE_UNWRAP_IF_ERR(err, json)) {
        co_return Err(fmt::format("Ping returned non-JSON response: {}", err));
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
