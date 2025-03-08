pub(crate) trait IntoError {
    type Value;

    fn into_error(self) -> Result<Self::Value, napi_ohos::Error>;
}

impl<T> IntoError for Result<T, russh::Error> {
    type Value = T;

    fn into_error(self) -> napi_ohos::Result<Self::Value> {
        self.map_err(|err| {
            napi_ohos::Error::new(napi_ohos::Status::GenericFailure, err.to_string())
        })
    }
}

impl<T> IntoError for Result<T, russh_keys::Error> {
    type Value = T;

    fn into_error(self) -> napi_ohos::Result<Self::Value> {
        self.map_err(|err| {
            napi_ohos::Error::new(napi_ohos::Status::GenericFailure, err.to_string())
        })
    }
}
