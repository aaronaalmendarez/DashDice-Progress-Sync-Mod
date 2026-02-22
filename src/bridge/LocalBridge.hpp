#pragma once

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_set>

#include <Geode/Geode.hpp>
#include <Geode/binding/LevelManagerDelegate.hpp>

namespace dashdice {

class LocalBridge final : public LevelManagerDelegate {
public:
    static LocalBridge& get();

    void onMenuReady();
    void shutdown();
    void openLevelFromRemote(int levelId);

    void loadLevelsFinished(cocos2d::CCArray* levels, char const* key) override;
    void loadLevelsFailed(char const* key) override;
    void loadLevelsFinished(cocos2d::CCArray* levels, char const* key, int type) override;
    void loadLevelsFailed(char const* key, int type) override;
    void setupPageInfo(gd::string info, char const* key) override;

private:
    LocalBridge() = default;
    ~LocalBridge() = default;

    bool isBridgeEnabled() const;
    bool isDebugEnabled() const;
    int bridgePort() const;
    std::string bridgeAllowedOriginsCsv() const;
    std::string openEndpoint() const;
    std::string requestId();

    void ensureServerState();
    bool startServer(int port);
    void stopServer();

    void serverLoop();
    void handleClient(int clientFd);

    void queueOpenLevel(int levelId);
    void openLevelInGame(int levelId);
    void completePendingOpen();
    void restoreLevelDelegate();
    void openResolvedLevel(GJGameLevel* level);

    void queuePairPrompt(std::string code, std::string claimUrl, std::string origin);
    void beginPairClaim(std::string code, std::string claimUrl, std::string origin);
    arc::Future<geode::Result<>> claimPairAsync(std::string code, std::string claimUrl);

    bool isOriginAllowed(std::string const& origin) const;
    std::unordered_set<std::string> parseAllowedOrigins() const;

    std::atomic<bool> m_running { false };
    std::thread m_serverThread;
    int m_serverPort = 0;
    std::intptr_t m_listenFd = -1;
    std::string m_bridgeToken;

    std::mutex m_stateMutex;
    bool m_pairClaimInFlight = false;

    int m_pendingOpenLevelId = 0;
    LevelManagerDelegate* m_prevLevelManagerDelegate = nullptr;
};

} // namespace dashdice
