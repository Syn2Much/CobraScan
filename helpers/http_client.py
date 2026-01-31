#!/usr/bin/env python3
"""
HTTP Client Helper
Rotation-aware HTTP requests using ProxyManager
"""

import urllib3

urllib3.disable_warnings()

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
    max_retries=10,
):
    """Perform an HTTP request with proxy rotation.

    - When proxies are loaded, ONLY uses proxies (no direct IP fallback)
    - Keeps retrying different proxies (supports rotating proxies)
    - Only falls back to direct connection if NO proxies are loaded
    """
    proxy_timeout = min(timeout or 10, 5)
    last_error = None

    proxies_available = proxy_manager.is_loaded() if proxy_manager else False

    if proxies_available:
        # When proxies are enabled, NEVER fall back to direct IP
        # Keep trying proxies (could be rotating proxy that needs retries)
        proxy_count = proxy_manager.get_count()
        # More attempts for single proxy (could be rotating), fewer for multiple
        attempts = max_retries if proxy_count == 1 else proxy_count * 3

        for attempt in range(attempts):
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

        # All proxy attempts failed - do NOT fall back to direct IP
        raise Exception(f"All proxy attempts failed for {url}: {last_error}")

    # Only use direct request when NO proxies are loaded
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
        resp._used_proxy = None
        return resp
    except RequestException as e:
        last_error = e

    raise Exception(f"Error fetching {url}: {last_error}")


def get(url: str, **kwargs):
    """Convenience GET wrapper using rotation."""
    return request_with_rotation("GET", url, **kwargs)
