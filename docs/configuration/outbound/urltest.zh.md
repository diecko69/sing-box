### 结构

```json
{
  "type": "urltest",
  "tag": "auto",
  
  "outbounds": [
    "proxy-a",
    "proxy-b",
    "proxy-c"
  ],
  "providers": [
    "provider-a",
    "provider-b",
  ],
  "url": "https://www.gstatic.com/generate_204",
  "interval": "1m",
  "tolerance": 50
}
```

### 字段

#### outbounds

用于测试的出站标签列表。

#### providers

用于测试的[订阅](/zh/configuration/provider)标签列表。

#### url

用于测试的链接。默认使用 `https://www.gstatic.com/generate_204`。

#### interval

测试间隔。 默认使用 `1m`。

#### tolerance

以毫秒为单位的测试容差。 默认使用 `50`。
