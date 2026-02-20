#include <Geode/Geode.hpp>

#include <Geode/modify/MenuLayer.hpp>
#include <Geode/modify/PlayLayer.hpp>

#include "sync/SyncManager.hpp"

using namespace geode::prelude;

class $modify(ProgressSyncPlayLayer, PlayLayer) {
    void onQuit() {
        if (m_level != nullptr) {
            dashdice::SyncManager::get().enqueueFromLevel(m_level, false);
        }
        PlayLayer::onQuit();
    }

    void levelComplete() {
        if (m_level != nullptr) {
            dashdice::SyncManager::get().enqueueFromLevel(m_level, true);
        }
        PlayLayer::levelComplete();
    }
};

class $modify(ProgressSyncMenuLayer, MenuLayer) {
    bool init() {
        if (!MenuLayer::init()) {
            return false;
        }
        dashdice::SyncManager::get().onMenuReady();
        return true;
    }
};
