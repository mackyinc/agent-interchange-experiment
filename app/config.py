"""Editable, conservative heuristics used by the observer."""

AI_SIGNATURES = (
    ("GPTBot", "UA matched configured signature GPTBot"),
    ("ChatGPT-User", "UA matched configured signature ChatGPT-User"),
    ("ClaudeBot", "UA matched configured signature ClaudeBot"),
    ("anthropic-ai", "UA matched configured signature anthropic-ai"),
    ("PerplexityBot", "UA matched configured signature PerplexityBot"),
    ("Google-Extended", "UA matched configured signature Google-Extended"),
    ("Bytespider", "UA matched configured signature Bytespider"),
    ("CCBot", "UA matched configured signature CCBot"),
    ("Amazonbot", "UA matched configured signature Amazonbot"),
    ("Applebot-Extended", "UA matched configured signature Applebot-Extended"),
)

SEARCH_SIGNATURES = (
    ("Googlebot", "UA matched configured signature Googlebot"),
    ("bingbot", "UA matched configured signature bingbot"),
    ("BingPreview", "UA matched configured signature BingPreview"),
    ("YandexBot", "UA matched configured signature YandexBot"),
    ("DuckDuckBot", "UA matched configured signature DuckDuckBot"),
    ("Baiduspider", "UA matched configured signature Baiduspider"),
    ("Slurp", "UA matched configured signature Slurp"),
    ("Applebot", "UA matched configured signature Applebot"),
)

AUTOMATION_SIGNATURES = (
    ("HeadlessChrome", "UA matched configured signature HeadlessChrome"),
    ("Playwright", "UA matched configured signature Playwright"),
    ("Puppeteer", "UA matched configured signature Puppeteer"),
    ("Selenium", "UA matched configured signature Selenium"),
    ("webdriver", "UA matched configured signature webdriver"),
)

CLI_SIGNATURES = (
    ("curl/", "UA matched configured signature curl"),
    ("Wget/", "UA matched configured signature Wget"),
    ("python-requests", "UA matched configured signature python-requests"),
    ("httpx", "UA matched configured signature httpx"),
    ("aiohttp", "UA matched configured signature aiohttp"),
)

GENERIC_CRAWLER_SIGNATURES = (
    ("crawler", "UA matched generic crawler signature"),
    ("spider", "UA matched generic crawler signature"),
    ("bot/", "UA matched generic crawler signature"),
    ("bot ", "UA matched generic crawler signature"),
    ("slurp", "UA matched generic crawler signature"),
)

SCANNER_PATH_SIGNATURES = (
    ("wp-admin", "path pattern resembles WordPress scanner"),
    ("wp-login", "path pattern resembles WordPress scanner"),
    ("/.env", "path pattern resembles secret-file scanner"),
    ("phpmyadmin", "path pattern resembles phpMyAdmin scanner"),
    ("vendor/phpunit", "path pattern resembles PHPUnit scanner"),
    ("/.git", "path pattern resembles Git metadata scanner"),
    ("cgi-bin", "path pattern resembles CGI scanner"),
    ("actuator", "path pattern resembles framework scanner"),
)

