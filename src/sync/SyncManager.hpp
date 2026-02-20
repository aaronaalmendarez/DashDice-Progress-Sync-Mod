#pragma once

#include <atomic>
#include <tuple>
#include <unordered_map>

#include <Geode/Geode.hpp>
#include <Geode/Result.hpp>
#include <Geode/binding/GJGameLevel.hpp>
#include <matjson.hpp>

namespace dashdice {
class SyncManager final {
public:
    static SyncManager& get();

    void enqueueFromLevel(GJGameLevel* level, bool levelCompleted);
    void onMenuReady();
    void flushQueue();

private:
    SyncManager() = default;

    bool isEnabled() const;
    bool isDebugEnabled() const;
    std::string serverUrl() const;
    std::string apiKey() const;
    int timeoutSeconds() const;

    matjson::Value loadQueue() const;
    void saveQueue(const matjson::Value& queue) const;
    void appendQueue(const matjson::Value& payload);

    void runPing();
    void runFlush();
    arc::Future<geode::Result<>> pingAsync();
    arc::Future<geode::Result<>> flushAsync();
    arc::Future<geode::Result<matjson::Value>> postPayload(const matjson::Value& payload);
    void maybeWarnNoAccount();

    std::atomic<bool> m_pinging { false };
    std::atomic<bool> m_flushing { false };
    bool m_warnedNoAccount = false;
    std::unordered_map<int, std::tuple<int, int, int>> m_lastSeenByLevel;
};
} // namespace dashdice
