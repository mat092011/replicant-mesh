class ConnectorError(Exception):
    def __init__(self, code, message):
        self.code = str(code)[:64]
        self.message = str(message)[:256]
        super().__init__(f"{self.code}: {self.message}")


class FeatureUnavailable(ConnectorError):
    pass
