## 1.3.1

#### new feature
Header <kbd>DEBUG-UPSTREAM</kbd> added .
when header <kbd>DEBUG-UPSTREAM</kbd> found, 
kuafu return backend directly.

#### path based configure

When looking for upstream,<kbd>pathConfig</kbd> has higher priority.
There are two matching method:
- path with <kbd>*</kbd> suffix, kuafu use strings.HasPrefix() to decide if the path hits the rule.
- path without <kbd>*</kbd> suffix,kuafu use <kbd>==</kbd> to decide if the rule hits.
```toml
[host."mac.shifen.de"]
	rateLimit={"cap"=100,"quantum"=60}
	pathConfig =[
		{path="/api/v2/*",backends=["127.0.0.1:8081"]},
		{path="/api",backends=["127.0.0.1:8080"]},
	]
```
