"""Fetch node for gathering PSIRT data from multiple sources."""

import asyncio
from typing import Dict, Any, List
from ..state import PSIRTState, RawAdvisory
from ...ingestion.cisco_api import CiscoOpenVulnAPI
from ...ingestion.web_scraper import CiscoAdvisoryScraper


async def _fetch_from_api(products: List[str]) -> List[Dict[str, Any]]:
    """Fetch advisories from Cisco OpenVuln API."""
    api = CiscoOpenVulnAPI()
    advisories = []

    try:
        # Fetch critical and high severity
        for severity in ["critical", "high"]:
            try:
                results = await api.get_advisories_by_severity(severity, limit=50)
                for adv in results:
                    advisories.append({
                        "source": "api",
                        "advisory_id": adv.advisory_id,
                        "title": adv.advisory_title,
                        "severity": adv.severity,
                        "cve_ids": adv.cve_ids,
                        "cvss_score": adv.cvss_base_score,
                        "summary": adv.summary,
                        "description": "",
                        "affected_products": adv.affected_products,
                        "workarounds": adv.workarounds,
                        "fixed_software": adv.fixed_software,
                        "url": adv.publication_url,
                        "raw_data": adv.raw_data
                    })
            except Exception as e:
                print(f"Error fetching {severity} advisories from API: {e}")

        # Fetch by product
        for product in products:
            try:
                results = await api.get_advisories_by_product(product, limit=30)
                for adv in results:
                    advisories.append({
                        "source": "api",
                        "advisory_id": adv.advisory_id,
                        "title": adv.advisory_title,
                        "severity": adv.severity,
                        "cve_ids": adv.cve_ids,
                        "cvss_score": adv.cvss_base_score,
                        "summary": adv.summary,
                        "description": "",
                        "affected_products": adv.affected_products,
                        "workarounds": adv.workarounds,
                        "fixed_software": adv.fixed_software,
                        "url": adv.publication_url,
                        "raw_data": adv.raw_data
                    })
            except Exception as e:
                print(f"Error fetching advisories for {product} from API: {e}")

    except Exception as e:
        print(f"API fetch error: {e}")

    return advisories


async def _fetch_from_scraper(products: List[str]) -> List[Dict[str, Any]]:
    """Fetch advisories by scraping Cisco Security Center."""
    scraper = CiscoAdvisoryScraper()
    advisories = []

    try:
        # Scrape critical advisories
        critical = await scraper.scrape_critical_advisories(limit=20)
        for adv in critical:
            advisories.append({
                "source": "scraper",
                "advisory_id": adv.advisory_id,
                "title": adv.title,
                "severity": adv.severity,
                "cve_ids": adv.cve_ids,
                "cvss_score": None,
                "summary": adv.summary,
                "description": adv.description,
                "affected_products": [adv.affected_products] if adv.affected_products else [],
                "workarounds": [adv.workarounds] if adv.workarounds else [],
                "fixed_software": [adv.fixed_software] if adv.fixed_software else [],
                "url": adv.url,
                "raw_data": {"raw_html": adv.raw_html[:1000]}  # Truncate HTML
            })

        # Check if IOS XR or IOS XE in products
        for product in products:
            product_lower = product.lower()
            if "xr" in product_lower or "ios-xr" in product_lower:
                xr_advisories = await scraper.scrape_ios_xr_advisories(limit=30)
                for adv in xr_advisories:
                    advisories.append({
                        "source": "scraper",
                        "advisory_id": adv.advisory_id,
                        "title": adv.title,
                        "severity": adv.severity,
                        "cve_ids": adv.cve_ids,
                        "cvss_score": None,
                        "summary": adv.summary,
                        "description": adv.description,
                        "affected_products": [adv.affected_products] if adv.affected_products else [],
                        "workarounds": [adv.workarounds] if adv.workarounds else [],
                        "fixed_software": [adv.fixed_software] if adv.fixed_software else [],
                        "url": adv.url,
                        "raw_data": {}
                    })

            if "xe" in product_lower or "ios-xe" in product_lower:
                xe_advisories = await scraper.scrape_ios_xe_advisories(limit=30)
                for adv in xe_advisories:
                    advisories.append({
                        "source": "scraper",
                        "advisory_id": adv.advisory_id,
                        "title": adv.title,
                        "severity": adv.severity,
                        "cve_ids": adv.cve_ids,
                        "cvss_score": None,
                        "summary": adv.summary,
                        "description": adv.description,
                        "affected_products": [adv.affected_products] if adv.affected_products else [],
                        "workarounds": [adv.workarounds] if adv.workarounds else [],
                        "fixed_software": [adv.fixed_software] if adv.fixed_software else [],
                        "url": adv.url,
                        "raw_data": {}
                    })

    except Exception as e:
        print(f"Scraper fetch error: {e}")

    return advisories


def _deduplicate_advisories(advisories: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Remove duplicate advisories, preferring API data over scraped data."""
    seen = {}
    for adv in advisories:
        adv_id = adv.get("advisory_id", "")
        if not adv_id:
            continue

        if adv_id not in seen:
            seen[adv_id] = adv
        elif adv["source"] == "api" and seen[adv_id]["source"] == "scraper":
            # Prefer API data
            seen[adv_id] = adv

    return list(seen.values())


async def fetch_psirt_node_async(state: PSIRTState) -> Dict[str, Any]:
    """Async version of fetch node."""
    messages = ["Starting PSIRT data fetch..."]
    errors = []

    # Determine products to check
    products = state.get("products_to_check", [])
    if not products:
        # Extract from inventory
        inventory = state.get("device_inventory", [])
        products = list(set(
            item.get("router_type", "")
            for item in inventory
            if item.get("router_type")
        ))

    if not products:
        products = ["IOS XR", "IOS XE", "ASR", "NCS"]

    messages.append(f"Fetching advisories for products: {', '.join(products)}")

    # Fetch from both sources concurrently
    try:
        api_task = _fetch_from_api(products)
        scraper_task = _fetch_from_scraper(products)

        api_results, scraper_results = await asyncio.gather(
            api_task, scraper_task, return_exceptions=True
        )

        # Handle exceptions
        all_advisories = []

        if isinstance(api_results, Exception):
            errors.append(f"API fetch failed: {str(api_results)}")
        else:
            all_advisories.extend(api_results)
            messages.append(f"Fetched {len(api_results)} advisories from API")

        if isinstance(scraper_results, Exception):
            errors.append(f"Scraper fetch failed: {str(scraper_results)}")
        else:
            all_advisories.extend(scraper_results)
            messages.append(f"Fetched {len(scraper_results)} advisories from scraper")

        # Deduplicate
        unique_advisories = _deduplicate_advisories(all_advisories)
        messages.append(f"Total unique advisories: {len(unique_advisories)}")

    except Exception as e:
        errors.append(f"Fetch error: {str(e)}")
        unique_advisories = []

    return {
        "raw_advisories": unique_advisories,
        "current_step": "fetched",
        "messages": messages,
        "errors": errors
    }


def fetch_psirt_node(state: PSIRTState) -> Dict[str, Any]:
    """
    Fetch PSIRT data from Cisco API and web scraper.

    This node:
    1. Determines which products to check from inventory or defaults
    2. Fetches advisories from Cisco OpenVuln API
    3. Scrapes advisories from Cisco Security Center
    4. Deduplicates and merges results
    """
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    return loop.run_until_complete(fetch_psirt_node_async(state))
