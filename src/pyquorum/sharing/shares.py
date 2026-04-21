import base64
import json
from ..exceptions import InvalidShareError

class Shares():
    """
    Class for shares

    Parameters
    ----------
    shares: list[str]
        splitted pieces of secret key
    """
    def __init__(self, shares: list[str]):
        
        if not isinstance(shares, list):
            raise InvalidShareError(f" Shares must be list, not {type(shares)}")
        
        for share in shares:
            if not isinstance(share, str):
                raise InvalidShareError(f"Share must be String, not {type(share)}")
        
        index = [i.split(":")[0] for i in shares]
        source_shares = [share.split(":",1)[1] for share in shares]
        self.shares = {i: s for i, s in zip(index, source_shares)}

    def to_base64(self):
        """
        Serialize to base64 format
        """
        return {i: base64.b64encode(share.encode('utf-8')).decode('utf-8') for i, share in self.shares.items()}
    
    def to_json(self):
        """
        Serialize to json format
        """
        data = self.to_base64()
        return json.dumps(data)
    
    @classmethod
    def from_base64(cls, base64_shares: dict[int, str]):
        """
        Serialize from base64 to dictionary

        Parameters
        ----------
        base64_shares: dict[int, str]
            splitted base64 pieces of secret key
        """
        list_shares = [f"{i}:{base64.b64decode(base64_share).decode('utf-8')}" for i, base64_share in base64_shares.items()]
        return cls(list_shares)

    @classmethod
    def from_json(cls, json_shares):
        """
        Serialize from json and base64 to dictionary
        """
        data = json.loads(json_shares)
        return cls.from_base64(data)
    
    def to_raw(self) -> list[str]:
        return [f"{i}:{s}" for i, s in self.shares.items()]