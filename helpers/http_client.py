#!/usr/bin/env python3
"""
HTTP Client Helper
Rotation-aware HTTP requests using ProxyManager
"""

import requests
from requests.exceptions import (
    RequestException,
    ProxyError,
    ConnectTimeout,
    ReadTimeout,
)


def request_with_rotation(
    method: str,
    url: str,
    *,
    proxy_manager=None,
    timeout=10,
    allow_redirects=True,
    verify=True,
    headers=None,
    params=None,
    data=None,
    json=None,
):
    """Perform an HTTP request with fast proxy rotation.

    - Tries available proxies quickly (min(timeout, 5s)) until one succeeds.
    - Marks failed proxies and rotates to the next.
    - Falls back to a direct connection once if all proxies fail.
    """
    proxy_timeout = min(timeout or 10, 5)
    last_error = None

    proxies_available = proxy_manager.is_loaded() if proxy_manager else False
    max_attempts = (proxy_manager.get_count() if proxies_available else 1) * 2 or 1

    if proxies_available:
        for _ in range(max_attempts):
            proxy_dict = proxy_manager.get_proxy()
            try:
                resp = requests.request(
                    method,
                    url,
                    timeout=proxy_timeout,
                    allow_redirects=allow_redirects,
                    verify=verify,
                    proxies=proxy_dict,
                    headers=headers,
                    params=params,
                    data=data,
                    json=json,
                )
                resp.raise_for_status()
                # Annotate response with the proxy used
                try:
                    resp._used_proxy = (
                        proxy_dict.get("http")
                        if isinstance(proxy_dict, dict)
                        else proxy_dict
                    )
                except Exception:
                    resp._used_proxy = None
                return resp
            except (ProxyError, ConnectTimeout, ReadTimeout) as e:
                last_error = e
                if proxy_manager:
                    proxy_manager.mark_failed(proxy_dict)
                    proxy_manager.get_next_proxy()
                continue
            except RequestException as e:
                last_error = e
                if proxy_manager:
                    proxy_manager.mark_failed(proxy_dict)
                    proxy_manager.get_next_proxy()
                continue

    # Fallback direct request
    try:
        resp = requests.request(
            method,
            url,
            timeout=timeout,
            allow_redirects=allow_redirects,
            verify=verify,
            proxies=None,
            headers=headers,
            params=params,
            data=data,
            json=json,
        )
        resp.raise_for_status()
        # Direct connection (no proxy)
        resp._used_proxy = None
        return resp
    except RequestException as e:
        last_error = e

    raise Exception(f"Error fetching {url}: {last_error}")


def get(url: str, **kwargs):
    """Convenience GET wrapper using rotation."""
    return request_with_rotation("GET", url, **kwargs)
