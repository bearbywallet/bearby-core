use config::storage::ADDRESS_BOOK_DB_KEY_V1;
use errors::background::BackgroundError;
use proto::address::Address;

use crate::book::AddressBookEntry;
use crate::{Background, Result};

pub trait AddressBookManagement {
    type Error;

    fn get_address_book(&self) -> Vec<AddressBookEntry>;
    fn add_to_address_book(
        &self,
        address: AddressBookEntry,
    ) -> std::result::Result<(), Self::Error>;
    fn remove_from_address_book(&self, address: &Address) -> std::result::Result<(), Self::Error>;
}

impl AddressBookManagement for Background {
    type Error = BackgroundError;

    fn remove_from_address_book(&self, address: &Address) -> std::result::Result<(), Self::Error> {
        let mut book = self.get_address_book();

        book.retain(|entry| entry.addr != *address);

        self.storage.set_versioned(ADDRESS_BOOK_DB_KEY_V1, &book)?;
        self.storage.flush()?;

        Ok(())
    }

    fn get_address_book(&self) -> Vec<AddressBookEntry> {
        self.storage
            .get_versioned::<Vec<AddressBookEntry>>(ADDRESS_BOOK_DB_KEY_V1)
            .unwrap_or_else(|_| Vec::with_capacity(1))
    }

    fn add_to_address_book(&self, address: AddressBookEntry) -> Result<()> {
        let mut book = self.get_address_book();

        if book.iter().any(|c| c.addr == address.addr) {
            return Err(BackgroundError::AddressAlreadyExists(
                address.addr.auto_format(),
            ));
        }

        book.push(address);

        self.storage.set_versioned(ADDRESS_BOOK_DB_KEY_V1, &book)?;
        self.storage.flush()?;

        Ok(())
    }
}

#[cfg(test)]
mod tests_background {
    use proto::address::Address;
    use rand::RngExt;

    use crate::bg_storage::StorageManagement;

    use super::*;

    fn setup_test_background() -> (Background, String) {
        let mut rng = rand::rng();
        let dir = format!("/tmp/{}", rng.random::<u64>());
        let bg = Background::from_storage_path(&dir).unwrap();
        (bg, dir)
    }

    #[test]
    fn test_address_book() {
        let (bg, dir) = setup_test_background();
        let book = bg.get_address_book();
        assert!(book.is_empty());

        let name = "Test Contact".to_string();
        let address =
            Address::from_eth_address("0x1234567890123456789012345678901234567890").unwrap();
        let entry = AddressBookEntry {
            name,
            addr: address.clone(),
            net: 0,
            slip44: 60,
        };

        // Test adding first address
        bg.add_to_address_book(entry.clone()).unwrap();

        let book = bg.get_address_book();
        assert_eq!(book.len(), 1);
        assert_eq!(&book[0].name, "Test Contact");
        assert_eq!(&book[0].addr, &address);

        let name2 = "Second Contact".to_string();
        let address2 =
            Address::from_eth_address("0xabcdefabcdefabcdefabcdefabcdefabcdefabcd").unwrap();
        let entry2 = AddressBookEntry {
            name: name2,
            addr: address2.clone(),
            net: 0,
            slip44: 60,
        };

        // Test adding second address
        bg.add_to_address_book(entry2.clone()).unwrap();

        // Verify both addresses exist
        let book = bg.get_address_book();
        assert_eq!(book.len(), 2);
        assert_eq!(book[1].name, "Second Contact");
        assert_eq!(book[1].addr, address2);

        // Test removing first address
        bg.remove_from_address_book(&address).unwrap();
        let book = bg.get_address_book();
        assert_eq!(book.len(), 1);
        assert_eq!(book[0].name, "Second Contact");
        assert_eq!(book[0].addr, address2);

        // Test removing second address
        bg.remove_from_address_book(&address2).unwrap();
        let book = bg.get_address_book();
        assert!(book.is_empty());

        // Test persistence - create new instance
        drop(bg);
        let bg2 = Background::from_storage_path(&dir).unwrap();
        let book = bg2.get_address_book();
        assert!(book.is_empty());
    }
}
