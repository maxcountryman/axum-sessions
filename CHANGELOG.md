# 0.4.2

- Allow setting HttpOnly of cookie [PR #30](https://github.com/maxcountryman/axum-sessions/pull/30)
- Resist session name fingerprinting [PR #36](https://github.com/maxcountryman/axum-sessions/pull/36)

# 0.4.1

- Update axum to v0.6.0

# 0.4.0

- Avoid storing cookie when not required [PR #15](https://github.com/maxcountryman/axum-sessions/pull/15)

# 0.3.2

- Search every Cookie header for session cookie [PR #14](https://github.com/maxcountryman/axum-sessions/pull/14)

# 0.3.1

- Derive `Debug` for `WritableSession` and `ReadableSession` ensuring consistency with `Session`

# 0.3.0

- Session regeneration support [PR #6](https://github.com/maxcountryman/axum-sessions/pull/6)

# 0.2.0

- On session destroy, unset cookie on client [PR #4](https://github.com/maxcountryman/axum-sessions/pull/4)

# 0.1.1

- Handle multiple cookie values [PR #2](https://github.com/maxcountryman/axum-sessions/pull/2)

# 0.1.0

- Initial release :tada:
