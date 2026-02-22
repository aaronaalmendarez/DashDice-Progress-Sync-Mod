#include <Geode/Geode.hpp>

#include <Geode/modify/AppDelegate.hpp>
#include <Geode/modify/CCScheduler.hpp>
#include <Geode/modify/GJGarageLayer.hpp>
#include <Geode/modify/MenuLayer.hpp>
#include <Geode/modify/PlayLayer.hpp>

#include "bridge/LocalBridge.hpp"
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
        dashdice::LocalBridge::get().onMenuReady();
        return true;
    }
};

class $modify(ProgressSyncGarageLayer, GJGarageLayer) {
    void onSelect(cocos2d::CCObject* sender) {
        GJGarageLayer::onSelect(sender);
        dashdice::SyncManager::get().onProfilePossiblyChanged();
    }

    void playerColorChanged() {
        GJGarageLayer::playerColorChanged();
        dashdice::SyncManager::get().onProfilePossiblyChanged();
    }

    void onToggleItem(cocos2d::CCObject* sender) {
        GJGarageLayer::onToggleItem(sender);
        dashdice::SyncManager::get().onProfilePossiblyChanged();
    }
};

class $modify(ProgressSyncAppDelegate, AppDelegate) {
    void trySaveGame(bool p0) {
        AppDelegate::trySaveGame(p0);
        dashdice::SyncManager::get().onProfilePossiblyChanged();
    }
};

class $modify(ProgressSyncScheduler, cocos2d::CCScheduler) {
    void update(float dt) {
        cocos2d::CCScheduler::update(dt);

        // Fallback for icon changes made by other mods (e.g. unlock-all tools)
        // that bypass normal garage callbacks. We keep this throttled.
        static float elapsed = 0.f;
        elapsed += dt;
        if (elapsed >= 3.0f) {
            elapsed = 0.f;
            dashdice::SyncManager::get().onProfilePossiblyChanged();
        }
    }
};
