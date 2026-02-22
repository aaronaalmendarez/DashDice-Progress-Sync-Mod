#pragma once

#include <atomic>
#include <cstdint>
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
    void onProfilePossiblyChanged();
    void flushQueue();

private:
    struct ProfileSnapshot {
        bool hasAccount = false;
        int accountId = 0;
        int userId = 0;
        std::string username;
        std::string playerName;

        bool hasStats = false;
        int stars = -1;
        int moons = -1;
        int demons = -1;
        int userCoins = -1;
        int secretCoins = -1;

        int iconCube = -1;
        int iconShip = -1;
        int iconBall = -1;
        int iconUfo = -1;
        int iconWave = -1;
        int iconRobot = -1;
        int iconSpider = -1;
        int iconSwing = -1;
        int iconJetpack = -1;
        int color1 = -1;
        int color2 = -1;
        int glowEnabled = -1;
    };

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
    ProfileSnapshot collectProfileSnapshot();
    void requestProfileSnapshotIfNeeded(int accountId, int userId);
    void runCommandPoll();
    void ensureCommandPollLoop();
    arc::Future<geode::Result<>> pingAsync();
    arc::Future<geode::Result<>> flushAsync();
    arc::Future<geode::Result<>> pollCommandsAsync();
    arc::Future<geode::Result<matjson::Value>> postPayload(const matjson::Value& payload);
    void maybeWarnNoAccount();

    std::atomic<bool> m_pinging { false };
    std::atomic<bool> m_flushing { false };
    std::atomic<bool> m_pollingCommands { false };
    std::atomic<bool> m_commandLoopStarted { false };
    bool m_warnedNoAccount = false;
    std::int64_t m_lastProfileRequestMs = 0;
    std::int64_t m_lastProfilePingMs = 0;
    std::string m_lastProfileSignature;
    std::unordered_map<int, std::tuple<int, int, int>> m_lastSeenByLevel;
};
} // namespace dashdice
