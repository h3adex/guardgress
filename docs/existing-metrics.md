# Existing Metrics

| Metric Name                            | Description                                                          | Type  | Labels                    | Notes                                                          |
|----------------------------------------|----------------------------------------------------------------------|-------|---------------------------|----------------------------------------------------------------|
| `http_https_request_count`             | Counts the total number of HTTP and HTTPS requests.                  | -     | `protocol`                | -                                                              |
| `http_https_request_status_code_count` | Tracks the count of HTTP and HTTPS requests by their status code.    | -     | `protocol`, `status_code` | -                                                              |
| `http_https_request_duration_seconds`  | Measures the duration of HTTP and HTTPS requests.                    | -     | `protocol`                | Buckets: Utilizes Prometheus's default bucket configuration.   |
| `concurrent_requests`                  | Indicates the current number of concurrent requests being processed. | Gauge | -                         | -                                                              |
| `rate_limit_blocks`                    | Counts the number of requests blocked due to rate limiting.          | -     | `protocol`, `endpoint`    | -                                                              |
| `tls_fingerprint_blocks`               | Monitors the number of requests blocked due to TLS fingerprinting.   | -     | `protocol`                | Future enhancements may include TLS fingerprint hash labeling. |
| `user_agent_blocks`                    | Tracks the number of requests blocked based on the user agent.       | -     | `protocol`, `user_agent`  | -                                                              |
| `watcher_ingresses_total`              | Total number of ingresses being watched.                             | Gauge | -                         | -                                                              |
| `watcher_ingress_limiters_total`       | Total number of ingress limiters currently active.                   | Gauge | -                         | -                                                              |
| `watcher_tls_certificates_total`       | Total number of TLS certificates being managed.                      | Gauge | -                         | -                                                              |
