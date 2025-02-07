# Contributing

## How it works?

**Linkook** scans social platforms based on the preset scan configuration file `provider.json`, performing the following checks:

- The scanner checks whether the account exists on the social platform based on the username.
- If the account exists and the platform allows linking other accounts, it uses `regex` to to search for other linked social accounts.
- It also checks whether the user’s profile contains email information, and if found, queries **HudsonRock’s Database**.
- If linked accounts are found, and their platforms also support linking, the scanner will add the newly discovered accounts to the scan queue.

**Linkook** relies on the **`provider.json`** file which contains a list of websites to search. Users can contribute by adding new sites to expand the tool’s search capabilities. This is where most contributions are needed. The basic format for adding new sites is as follows:

```json
"Website Name": {
        "mainUrl": "https://www.website.com",
        "profileUrl": "https://www.website.com/profile/^USER^",
        "queryUrl": "https://www.website.com/api/user",
        "regexUrl": "https://(?:www.|m.)?website.com/(?:user/|profile/|@)^USER^",
        "keyword": {
            "Match": ["followers", "following"],
            "notMatch": ["User does not exist"]
        },
        "isUserId": true,
        "isConnected": true,
        "hasEmail": false
    }
```

## Parameter Explanation

**`mainUrl (optional)`:**

- It defines the site’s main URL.

**`profileUrl (required)`**:

- It defines the format of a user profile URL on the site.
- Use `profileUrl` as a search-query template, with `^USER^` acting as the placeholder for the user parameter in the URL.
- In `Linkook`’s process of finding linked accounts, it can also serve as a **regex pattern** for lookups.

**`queryUrl (optional)`**:

- It defines the URL which used to request query.
- Some sites do not support direct requests to the `profileUrl` but allow alternative request URLs (for example, via an **API endpoint**).
- In `Linkook`, when searching a site, the request will first try the designated queryUrl, and if not applicable, it then falls back to the `profileUrl`.

**Other request options**:

- If the profile query requires additional parameters, such as using a `POST` request, modifying `headers`, or adding a `request body`, you can configure it as shown in the following format.

```json
"Website Name": {
        "request_method": "POST",
        "headers": {
        "Content-Type": "application/json"
        },
        "request_payload": { "PAYLOAD" : "BODY" }
    }
```

**`keyword (optional)`**:

- It defines the profile URL request detection pattern.
- In the keyword configuration, you can set either `Match` or `notMatch` (only one is needed), each defined as a list of multiple keywords.
- If you use `Match`, finding any of those keywords indicates that the user was located; if you use `notMatch`, encountering any listed keyword indicates that the user was not found.

> [!NOTE]
> keyword is optional. If no keyword is specified, `Linkook` will not send a request to query the user’s profile on that site;
>
> it will only look for profile characteristics when searching for linked accounts.

**`regexUrl (optional)`**:

- When searching for associated accounts, `Linkook` uses regex matching on the profile response.
- The regexUrl defines the specific **regex pattern**. Within it, you can simply include `^USER^` as the placeholder for the user parameter, and Linkook will transform it into the necessary regex at runtime.
- If regexUrl is not provided, `profileUrl` is used as the **default** regex pattern.

**`handle_regex (optional)`**:

- In certain situations, the response data is not a complete profile URL—only a **username/user ID** or, in the case of an API result, just the **social handle**.
- In those cases, you can define a `handle_regex` for the specific associated platform’s **regex pattern**.
- Likewise, if a general regex lookup cannot be used due to encoded URLs or escaped characters in the returned links, you can fix it by setting `handle_regex`.

> [!NOTE]  
> If `handle_regex` is defined, `Linkook` will only use that custom regex for the corresponding website.
>
> See the **HackerOne** and **Hack The Box** examples for reference on how to configure.

```json
"handle_regex" : {
            "GitHub": "github_handle\":\"([^\"]+)",
            "LinkedIn": "linkedin_handle\":\"([^\"]+)",
        }
```

**`isUserId (optional: Default false)`**:

- It specifies whether the user-related parameter in the profile URL is a `user ID`.
- If set to **true**, when scanning for linked accounts, `Linkook` will skip adding that user ID to the **Related Username** list.

**`isConnected (optional: Default false)`**:

- It defines whether this site has an associated account by setting `isConnected`. If set to **true**, `Linkook` will parse the response text from the request to find any linked accounts.
- By default, `Linkook` only scans sites where `isConnected` is set to **true**.
- However, if you specify `--scan-all`, `Linkook` will attempt to scan all sites. (If no `keyword` is configured, `Linkook` cannot perform a profile scan regardless.)

**`hasEmail (optional: Default true)`**:

- It defines whether the scanned site has associated emails.
- If the site contains a large number of unrelated emails, setting `hasEmail` to **false** can prevent those irrelevant addresses from appearing in the scan results.
