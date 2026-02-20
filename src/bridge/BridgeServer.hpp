#pragma once

namespace dashdice {
class BridgeServer final {
public:
    static BridgeServer& get();

    void onMenuReady();

private:
    BridgeServer() = default;
    ~BridgeServer();

    BridgeServer(const BridgeServer&) = delete;
    BridgeServer& operator=(const BridgeServer&) = delete;
};
} // namespace dashdice
