use std::sync::Arc;

use crate::{bg_storage::StorageManagement, Result};

use crate::Background;
use errors::background::BackgroundError;
use settings::{
    browser::BrowserSettings,
    common_settings::CommonSettings,
    notifications::{NotificationState, Notifications},
    theme::Theme,
};

pub trait SettingsManagement {
    type Error;

    fn set_global_notifications(
        &self,
        global_enabled: bool,
    ) -> std::result::Result<(), Self::Error>;

    fn get_global_settings(&self) -> CommonSettings;

    fn set_wallet_notifications(
        &self,
        wallet_index: usize,
        notification: NotificationState,
    ) -> std::result::Result<(), Self::Error>;

    fn set_locale(&self, new_locale: Option<String>) -> std::result::Result<(), Self::Error>;

    fn set_theme(&self, new_theme: Theme) -> std::result::Result<(), Self::Error>;
    fn set_browser_settings(
        &self,
        new_settings: BrowserSettings,
    ) -> std::result::Result<(), Self::Error>;

    fn set_notifications(
        &self,
        new_notifications: Notifications,
    ) -> std::result::Result<(), Self::Error>;
}

impl SettingsManagement for Background {
    type Error = BackgroundError;

    fn get_global_settings(&self) -> CommonSettings {
        Background::load_global_settings(Arc::clone(&self.storage))
    }

    fn set_browser_settings(&self, new_settings: BrowserSettings) -> Result<()> {
        let mut global_settings = Background::load_global_settings(Arc::clone(&self.storage));

        global_settings.browser = new_settings;
        self.save_settings(global_settings)?;

        Ok(())
    }

    fn set_global_notifications(&self, global_enabled: bool) -> Result<()> {
        let mut global_settings = Background::load_global_settings(Arc::clone(&self.storage));

        global_settings.notifications.global_enabled = global_enabled;
        self.save_settings(global_settings)?;

        Ok(())
    }

    fn set_wallet_notifications(
        &self,
        wallet_index: usize,
        notification: NotificationState,
    ) -> Result<()> {
        let mut global_settings = Background::load_global_settings(Arc::clone(&self.storage));

        global_settings
            .notifications
            .wallet_states
            .insert(wallet_index, notification);
        self.save_settings(global_settings)?;

        Ok(())
    }

    fn set_locale(&self, new_locale: Option<String>) -> Result<()> {
        let mut global_settings = Background::load_global_settings(Arc::clone(&self.storage));

        global_settings.locale = new_locale;
        self.save_settings(global_settings)?;

        Ok(())
    }

    fn set_theme(&self, new_theme: Theme) -> Result<()> {
        let mut global_settings = Background::load_global_settings(Arc::clone(&self.storage));

        global_settings.theme = new_theme;
        self.save_settings(global_settings)?;

        Ok(())
    }

    fn set_notifications(&self, new_notifications: Notifications) -> Result<()> {
        let mut global_settings = Background::load_global_settings(Arc::clone(&self.storage));

        global_settings.notifications = new_notifications;
        self.save_settings(global_settings)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests_background {
    use super::*;
    use rand::RngExt;

    fn setup_test_background() -> (Background, String) {
        let mut rng = rand::rng();
        let dir = format!("/tmp/{}", rng.random::<u64>());
        let bg = Background::from_storage_path(&dir).unwrap();
        (bg, dir)
    }

    #[test]
    fn test_set_global_notifications() {
        let (bg, dir) = setup_test_background();

        // Test enabling notifications
        assert!(bg.set_global_notifications(true).is_ok());
        let settings = Background::load_global_settings(Arc::clone(&bg.storage));
        assert!(settings.notifications.global_enabled);

        // Test disabling notifications
        assert!(bg.set_global_notifications(false).is_ok());
        let settings = Background::load_global_settings(Arc::clone(&bg.storage));
        assert!(!settings.notifications.global_enabled);

        drop(bg);

        // Test persistence after reload
        let bg_reloaded = Background::from_storage_path(&dir).unwrap();
        let settings = Background::load_global_settings(Arc::clone(&bg_reloaded.storage));
        assert!(!settings.notifications.global_enabled);
    }

    #[test]
    fn test_set_wallet_notifications() {
        let (bg, dir) = setup_test_background();
        let test_state = NotificationState::all_enabled();
        let wallet_index = 1;

        // Test setting notification state
        assert!(bg
            .set_wallet_notifications(wallet_index, test_state.clone())
            .is_ok());
        let settings = Background::load_global_settings(Arc::clone(&bg.storage));
        assert_eq!(
            settings.notifications.wallet_states.get(&wallet_index),
            Some(&test_state)
        );

        drop(bg);

        // Test persistence after reload
        let bg_reloaded = Background::from_storage_path(&dir).unwrap();
        let settings = Background::load_global_settings(Arc::clone(&bg_reloaded.storage));
        assert_eq!(
            settings.notifications.wallet_states.get(&wallet_index),
            Some(&test_state)
        );
    }

    #[test]
    fn test_set_locale() {
        let (bg, dir) = setup_test_background();
        let test_locale = None;

        // Test setting locale
        assert!(bg.set_locale(test_locale.clone()).is_ok());
        let settings = Background::load_global_settings(Arc::clone(&bg.storage));
        assert_eq!(settings.locale, test_locale);

        drop(bg);

        // Test persistence after reload
        let bg_reloaded = Background::from_storage_path(&dir).unwrap();
        let settings = Background::load_global_settings(Arc::clone(&bg_reloaded.storage));
        assert_eq!(settings.locale, test_locale);
    }

    #[test]
    fn test_set_theme() {
        let (bg, dir) = setup_test_background();
        let test_theme = Theme {
            appearances: settings::theme::Appearances::Light,
            compact_numbers: true,
        };

        // Test setting theme
        assert!(bg.set_theme(test_theme.clone()).is_ok());
        let settings = Background::load_global_settings(Arc::clone(&bg.storage));
        assert_eq!(settings.theme, test_theme);

        drop(bg);

        // Test persistence after reload
        let bg_reloaded = Background::from_storage_path(&dir).unwrap();
        let settings = Background::load_global_settings(Arc::clone(&bg_reloaded.storage));
        assert_eq!(settings.theme, test_theme);
    }

    #[test]
    fn test_set_notifications() {
        let (bg, dir) = setup_test_background();
        let mut test_notifications = Notifications::default();

        test_notifications
            .wallet_states
            .insert(0, NotificationState::all_enabled());

        // Test setting notifications
        assert!(bg.set_notifications(test_notifications.clone()).is_ok());
        let settings = Background::load_global_settings(Arc::clone(&bg.storage));
        assert_eq!(settings.notifications, test_notifications);

        drop(bg);

        // Test persistence after reload
        let bg_reloaded = Background::from_storage_path(&dir).unwrap();
        let settings = Background::load_global_settings(Arc::clone(&bg_reloaded.storage));
        assert_eq!(settings.notifications, test_notifications);
    }

    #[test]
    fn test_settings_persistence() {
        let (bg, dir) = setup_test_background();

        // Make multiple settings changes
        assert!(bg.set_global_notifications(true).is_ok());
        assert!(bg
            .set_theme(Theme {
                compact_numbers: true,
                appearances: settings::theme::Appearances::System
            })
            .is_ok());
        assert!(bg.set_locale(None).is_ok());
        assert!(bg
            .set_wallet_notifications(1, NotificationState::all_enabled())
            .is_ok());

        drop(bg);

        // Verify all changes persist after reload
        let bg_reloaded = Background::from_storage_path(&dir).unwrap();
        let settings = Background::load_global_settings(Arc::clone(&bg_reloaded.storage));

        assert!(settings.notifications.global_enabled);
        assert_eq!(
            settings.theme,
            Theme {
                compact_numbers: true,
                appearances: settings::theme::Appearances::System
            }
        );
        assert_eq!(settings.locale, None);
        assert_eq!(
            settings.notifications.wallet_states.get(&1),
            Some(&NotificationState::all_enabled())
        );
    }
}
