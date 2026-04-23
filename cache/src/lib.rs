use errors::cache::CacheError;
use image::guess_format;
use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;

pub type Result<T> = std::result::Result<T, CacheError>;

pub struct Cache {
    cache_dir: PathBuf,
}

impl Cache {
    pub fn new(cache_dir: PathBuf) -> Result<Self> {
        fs::create_dir_all(&cache_dir).map_err(|e| CacheError::CreateDirError(e.to_string()))?;
        Ok(Self { cache_dir })
    }

    fn find_cached_file(&self, url_hash: &str) -> Option<String> {
        let possible_extensions = ["png", "jpg", "jpeg", "gif", "svg", "webp", "ico"];
        for ext in possible_extensions.iter() {
            let file_name = format!("{}.{}", url_hash, ext);
            let file_path = self.cache_dir.join(&file_name);

            if file_path.exists() {
                return Some(file_name);
            }
        }
        None
    }

    async fn save_downloaded_image(&self, url_hash: &str, bytes: &[u8]) -> Result<String> {
        let extension = self.detect_image_format(bytes)?;
        let file_name = format!("{}.{}", url_hash, extension);
        let file_path = self.cache_dir.join(&file_name);

        fs::write(&file_path, bytes).map_err(|e| CacheError::WriteFileError(e.to_string()))?;

        Ok(file_name)
    }

    pub async fn get_image_name(&self, url: &str) -> Result<String> {
        let url_hash = self.hash_url(url);

        if let Some(file_name) = self.find_cached_file(&url_hash) {
            return Ok(file_name);
        }

        let bytes = self.download_image(url).await?;
        self.save_downloaded_image(&url_hash, &bytes).await
    }

    pub async fn get_image_bytes(&self, url: &str) -> Result<(Vec<u8>, String)> {
        let url_hash = self.hash_url(url);

        if let Some(file_name) = self.find_cached_file(&url_hash) {
            let file_path = self.cache_dir.join(&file_name);
            let bytes =
                fs::read(&file_path).map_err(|e| CacheError::ReadFileError(e.to_string()))?;
            let extension = file_name
                .split('.')
                .next_back()
                .ok_or(CacheError::UnknownImageFormat)?
                .to_string();
            return Ok((bytes, extension));
        }

        let bytes = self.download_image(url).await?;
        let format = self.detect_image_format(&bytes)?;

        self.save_downloaded_image(&url_hash, &bytes).await?;

        Ok((bytes, format))
    }

    async fn download_image(&self, url: &str) -> Result<Vec<u8>> {
        let response = reqwest::get(url)
            .await
            .map_err(|e| CacheError::ReqwestError(e.to_string()))?;
        if !response.status().is_success() {
            return Err(CacheError::DownloadFileError(response.status().as_u16()));
        }

        Ok(response
            .bytes()
            .await
            .map_err(|e| CacheError::UnknownContent(e.to_string()))?
            .to_vec())
    }

    fn detect_image_format(&self, bytes: &[u8]) -> Result<String> {
        if self.is_svg(bytes) {
            return Ok("svg".to_string());
        }

        match guess_format(bytes) {
            Ok(format) => Ok(format.extensions_str()[0].to_string()),
            Err(_) => Err(CacheError::UnknownImageFormat),
        }
    }

    fn is_svg(&self, bytes: &[u8]) -> bool {
        if let Ok(content) = String::from_utf8(bytes.to_vec()) {
            content.trim_start().starts_with("<?xml") || content.trim_start().starts_with("<svg")
        } else {
            false
        }
    }

    fn hash_url(&self, url: &str) -> String {
        let mut hasher = DefaultHasher::new();
        url.hash(&mut hasher);
        format!("0x{:x}", hasher.finish())
    }
}

#[cfg(test)]
mod tests_cache {
    use crate::Cache;
    use rand::RngExt;
    use std::path::PathBuf;
    use tokio;

    fn setup_test_dir() -> String {
        format!("/tmp/{}", rand::rng().random::<u64>())
    }

    #[tokio::test]
    async fn test_get_cache_image() {
        let dir = setup_test_dir();
        let cache = Cache::new(PathBuf::from(dir)).unwrap();

        let url = "https://meta.viewblock.io/zilliqa.zil180v66mlw007ltdv8tq5t240y7upwgf7djklmwh/logo?t=dark";
        let cached_name = cache.get_image_name(url).await.unwrap();

        assert_eq!("0x1331b9c48bc9540.svg", cached_name);
        let cached_name = cache.get_image_name(url).await.unwrap();
        assert_eq!("0x1331b9c48bc9540.svg", cached_name);

        let (bytes, format) = cache.get_image_bytes(url).await.unwrap();
        assert!(!bytes.is_empty());
        assert_eq!("svg", format);
    }
}
