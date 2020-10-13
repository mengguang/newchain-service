# Common NewChain utility services.
1. ECDSA Recover:   
```
POST /crypto/ecdsa-recover HTTP/1.1
Host: localhost:3000
Content-Type: application/x-www-form-urlencoded

signature=1c704ddd843f742cd2ad4fc5be0f581498f9f8eb0fcb0cd4c0899c79a707d12417e185dc8d6bc7e391e47ceabe4a4d972d2e729effa5efcc44e9d02959c21448&message_hash=1b85d9cd435ec0e84c0105a1904ce1cd34094a94f3cc80e2ade9a9ed50081f93&v=1
```
```
{
    "result": "success",
    "public_key": "fea46be820c264b623e880b62b459bc2da21b392bbe72c7734ffc2e98c92c961bb6e0158593dd25137117eb5bbdbf3c1d9c1290eb12964ba19f17685f10144fc"
}
```
