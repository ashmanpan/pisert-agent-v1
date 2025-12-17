"""Cisco OpenVuln API client for fetching PSIRT advisories."""

import httpx
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
import asyncio
from tenacity import retry, stop_after_attempt, wait_exponential

from ..config import settings


@dataclass
class CiscoAdvisory:
    """Represents a Cisco Security Advisory."""
    advisory_id: str
    advisory_title: str
    cve_ids: List[str]
    cvss_base_score: Optional[float]
    severity: str
    first_published: str
    last_updated: str
    summary: str
    affected_products: List[str]
    fixed_software: List[str]
    workarounds: List[str]
    publication_url: str
    raw_data: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class CiscoOpenVulnAPI:
    """Client for Cisco OpenVuln API."""

    def __init__(
        self,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None
    ):
        self.client_id = client_id or settings.cisco_client_id
        self.client_secret = client_secret or settings.cisco_client_secret
        self.base_url = settings.cisco_api_base_url
        self.token_url = settings.cisco_token_url
        self._access_token: Optional[str] = None
        self._token_expires: Optional[datetime] = None

    async def _get_access_token(self) -> str:
        """Obtain OAuth2 access token from Cisco."""
        if self._access_token and self._token_expires:
            if datetime.now() < self._token_expires:
                return self._access_token

        async with httpx.AsyncClient() as client:
            response = await client.post(
                self.token_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.client_id,
                    "client_secret": self.client_secret
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            response.raise_for_status()
            data = response.json()

            self._access_token = data["access_token"]
            expires_in = data.get("expires_in", 3600)
            self._token_expires = datetime.now().replace(
                second=datetime.now().second + expires_in - 60
            )

            return self._access_token

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    async def _make_request(self, endpoint: str, params: Optional[Dict] = None) -> Dict:
        """Make authenticated request to Cisco API."""
        token = await self._get_access_token()

        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/{endpoint}",
                params=params,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/json"
                },
                timeout=30.0
            )
            response.raise_for_status()
            return response.json()

    def _parse_advisory(self, data: Dict) -> CiscoAdvisory:
        """Parse raw API response into CiscoAdvisory object."""
        return CiscoAdvisory(
            advisory_id=data.get("advisoryId", ""),
            advisory_title=data.get("advisoryTitle", ""),
            cve_ids=data.get("cves", []) if isinstance(data.get("cves"), list) else [],
            cvss_base_score=float(data.get("cvssBaseScore", 0)) if data.get("cvssBaseScore") else None,
            severity=data.get("sir", "Unknown"),
            first_published=data.get("firstPublished", ""),
            last_updated=data.get("lastUpdated", ""),
            summary=data.get("summary", ""),
            affected_products=self._extract_products(data),
            fixed_software=data.get("fixedSoftware", []) if isinstance(data.get("fixedSoftware"), list) else [],
            workarounds=data.get("workarounds", []) if isinstance(data.get("workarounds"), list) else [],
            publication_url=data.get("publicationUrl", ""),
            raw_data=data
        )

    def _extract_products(self, data: Dict) -> List[str]:
        """Extract affected products from advisory data."""
        products = []
        if "productNames" in data:
            products.extend(data["productNames"])
        if "platforms" in data:
            products.extend(data["platforms"])
        return list(set(products))

    async def get_advisory_by_id(self, advisory_id: str) -> Optional[CiscoAdvisory]:
        """Fetch a specific advisory by ID."""
        try:
            data = await self._make_request(f"advisory/{advisory_id}")
            if "advisories" in data and data["advisories"]:
                return self._parse_advisory(data["advisories"][0])
            return None
        except Exception as e:
            print(f"Error fetching advisory {advisory_id}: {e}")
            return None

    async def get_advisories_by_severity(
        self,
        severity: str = "critical",
        limit: int = 50
    ) -> List[CiscoAdvisory]:
        """Fetch advisories by severity level."""
        try:
            data = await self._make_request(
                f"severity/{severity}",
                params={"pageSize": limit}
            )
            advisories = []
            for item in data.get("advisories", []):
                advisories.append(self._parse_advisory(item))
            return advisories
        except Exception as e:
            print(f"Error fetching advisories by severity: {e}")
            return []

    async def get_advisories_by_product(
        self,
        product: str,
        limit: int = 50
    ) -> List[CiscoAdvisory]:
        """Fetch advisories affecting a specific product."""
        try:
            data = await self._make_request(
                f"product",
                params={"product": product, "pageSize": limit}
            )
            advisories = []
            for item in data.get("advisories", []):
                advisories.append(self._parse_advisory(item))
            return advisories
        except Exception as e:
            print(f"Error fetching advisories for product {product}: {e}")
            return []

    async def get_advisories_by_cve(self, cve_id: str) -> List[CiscoAdvisory]:
        """Fetch advisories by CVE ID."""
        try:
            data = await self._make_request(f"cve/{cve_id}")
            advisories = []
            for item in data.get("advisories", []):
                advisories.append(self._parse_advisory(item))
            return advisories
        except Exception as e:
            print(f"Error fetching advisories for CVE {cve_id}: {e}")
            return []

    async def get_ios_advisories(self, version: str) -> List[CiscoAdvisory]:
        """Fetch advisories affecting IOS/IOS-XE version."""
        try:
            data = await self._make_request(f"ios", params={"version": version})
            advisories = []
            for item in data.get("advisories", []):
                advisories.append(self._parse_advisory(item))
            return advisories
        except Exception as e:
            print(f"Error fetching IOS advisories: {e}")
            return []

    async def get_iosxr_advisories(self, version: str) -> List[CiscoAdvisory]:
        """Fetch advisories affecting IOS-XR version."""
        try:
            data = await self._make_request(f"iosxe", params={"version": version})
            advisories = []
            for item in data.get("advisories", []):
                advisories.append(self._parse_advisory(item))
            return advisories
        except Exception as e:
            print(f"Error fetching IOS-XR advisories: {e}")
            return []

    async def get_latest_advisories(self, limit: int = 100) -> List[CiscoAdvisory]:
        """Fetch the latest advisories."""
        try:
            data = await self._make_request("latest/100")
            advisories = []
            for item in data.get("advisories", []):
                advisories.append(self._parse_advisory(item))
            return advisories[:limit]
        except Exception as e:
            print(f"Error fetching latest advisories: {e}")
            return []

    async def fetch_all_relevant_advisories(
        self,
        products: List[str],
        severities: List[str] = None
    ) -> List[CiscoAdvisory]:
        """Fetch advisories for multiple products and severities."""
        if severities is None:
            severities = ["critical", "high"]

        all_advisories = {}

        # Fetch by severity
        for severity in severities:
            advisories = await self.get_advisories_by_severity(severity)
            for adv in advisories:
                all_advisories[adv.advisory_id] = adv

        # Fetch by product
        for product in products:
            advisories = await self.get_advisories_by_product(product)
            for adv in advisories:
                all_advisories[adv.advisory_id] = adv

        return list(all_advisories.values())


# Synchronous wrapper for non-async contexts
class CiscoOpenVulnAPISync:
    """Synchronous wrapper for CiscoOpenVulnAPI."""

    def __init__(self, client_id: Optional[str] = None, client_secret: Optional[str] = None):
        self._async_client = CiscoOpenVulnAPI(client_id, client_secret)

    def _run(self, coro):
        """Run async coroutine synchronously."""
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        return loop.run_until_complete(coro)

    def get_advisory_by_id(self, advisory_id: str) -> Optional[CiscoAdvisory]:
        return self._run(self._async_client.get_advisory_by_id(advisory_id))

    def get_advisories_by_severity(self, severity: str = "critical", limit: int = 50) -> List[CiscoAdvisory]:
        return self._run(self._async_client.get_advisories_by_severity(severity, limit))

    def get_advisories_by_product(self, product: str, limit: int = 50) -> List[CiscoAdvisory]:
        return self._run(self._async_client.get_advisories_by_product(product, limit))

    def get_latest_advisories(self, limit: int = 100) -> List[CiscoAdvisory]:
        return self._run(self._async_client.get_latest_advisories(limit))
