"""Web scraper for Cisco Security Advisories."""

import re
import httpx
from bs4 import BeautifulSoup
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
import asyncio
from tenacity import retry, stop_after_attempt, wait_exponential


@dataclass
class ScrapedAdvisory:
    """Represents a scraped Cisco Security Advisory."""
    advisory_id: str
    title: str
    severity: str
    cve_ids: List[str]
    first_published: str
    last_updated: str
    summary: str
    description: str
    affected_products: str
    workarounds: str
    fixed_software: str
    url: str
    raw_html: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class CiscoAdvisoryScraper:
    """Scraper for Cisco Security Center advisories."""

    BASE_URL = "https://sec.cloudapps.cisco.com"
    LISTING_URL = f"{BASE_URL}/security/center/publicationListing.x"
    ADVISORY_URL = f"{BASE_URL}/security/center/content/CiscoSecurityAdvisory"

    def __init__(self):
        self.session = None

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    async def _fetch_page(self, url: str, params: Optional[Dict] = None) -> str:
        """Fetch a page with retry logic."""
        async with httpx.AsyncClient(follow_redirects=True, timeout=30.0) as client:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
            }
            response = await client.get(url, params=params, headers=headers)
            response.raise_for_status()
            return response.text

    async def get_advisory_listing(
        self,
        severity: Optional[str] = None,
        product: Optional[str] = None,
        limit: int = 50
    ) -> List[Dict[str, str]]:
        """Get list of advisories from the publication listing page."""
        params = {
            "limit": limit,
            "sort": "-day_sir"
        }
        if severity:
            params["severity"] = severity
        if product:
            params["product"] = product

        html = await self._fetch_page(self.LISTING_URL, params)
        soup = BeautifulSoup(html, 'html.parser')

        advisories = []

        # Find advisory entries in the listing
        for row in soup.select('tr.ng-scope, div.security-advisory-item, a[href*="CiscoSecurityAdvisory"]'):
            try:
                advisory_data = self._parse_listing_row(row)
                if advisory_data:
                    advisories.append(advisory_data)
            except Exception:
                continue

        return advisories[:limit]

    def _parse_listing_row(self, row) -> Optional[Dict[str, str]]:
        """Parse a single row from the advisory listing."""
        # Try to find advisory link
        link = row.find('a', href=re.compile(r'cisco-sa-'))
        if not link:
            link = row if row.name == 'a' else None

        if not link:
            return None

        href = link.get('href', '')
        advisory_id_match = re.search(r'(cisco-sa-[\w-]+)', href)
        advisory_id = advisory_id_match.group(1) if advisory_id_match else ""

        title = link.get_text(strip=True) if link else ""

        # Try to find severity
        severity_elem = row.find(class_=re.compile(r'severity|sir', re.I))
        severity = severity_elem.get_text(strip=True) if severity_elem else "Unknown"

        # Try to find date
        date_elem = row.find(class_=re.compile(r'date|published', re.I))
        date = date_elem.get_text(strip=True) if date_elem else ""

        return {
            "advisory_id": advisory_id,
            "title": title,
            "severity": severity,
            "date": date,
            "url": href if href.startswith('http') else f"{self.BASE_URL}{href}"
        }

    async def get_advisory_details(self, advisory_id: str) -> Optional[ScrapedAdvisory]:
        """Scrape full details of a specific advisory."""
        url = f"{self.ADVISORY_URL}/{advisory_id}"

        try:
            html = await self._fetch_page(url)
            return self._parse_advisory_page(html, advisory_id, url)
        except Exception as e:
            print(f"Error scraping advisory {advisory_id}: {e}")
            return None

    def _parse_advisory_page(self, html: str, advisory_id: str, url: str) -> ScrapedAdvisory:
        """Parse the advisory detail page."""
        soup = BeautifulSoup(html, 'html.parser')

        # Extract title
        title_elem = soup.find('h1', class_='headline') or soup.find('h1')
        title = title_elem.get_text(strip=True) if title_elem else ""

        # Extract severity
        severity_elem = soup.find(class_=re.compile(r'severitycircle|badge-', re.I))
        severity = severity_elem.get_text(strip=True) if severity_elem else "Unknown"

        # Extract CVEs
        cve_pattern = re.compile(r'CVE-\d{4}-\d+', re.I)
        cves = list(set(cve_pattern.findall(html)))

        # Extract dates
        first_published = ""
        last_updated = ""
        for date_div in soup.find_all(class_=re.compile(r'date|published|updated', re.I)):
            text = date_div.get_text()
            if 'first' in text.lower() or 'published' in text.lower():
                date_match = re.search(r'\d{4}[-/]\d{2}[-/]\d{2}|\w+ \d+, \d{4}', text)
                if date_match:
                    first_published = date_match.group()
            elif 'last' in text.lower() or 'updated' in text.lower():
                date_match = re.search(r'\d{4}[-/]\d{2}[-/]\d{2}|\w+ \d+, \d{4}', text)
                if date_match:
                    last_updated = date_match.group()

        # Extract sections
        summary = self._extract_section(soup, ['summary', 'overview'])
        description = self._extract_section(soup, ['description', 'details', 'vulnerability'])
        affected = self._extract_section(soup, ['affected', 'products', 'vulnerable'])
        workarounds = self._extract_section(soup, ['workaround', 'mitigation'])
        fixed = self._extract_section(soup, ['fixed', 'software', 'solution'])

        return ScrapedAdvisory(
            advisory_id=advisory_id,
            title=title,
            severity=severity,
            cve_ids=cves,
            first_published=first_published,
            last_updated=last_updated,
            summary=summary,
            description=description,
            affected_products=affected,
            workarounds=workarounds,
            fixed_software=fixed,
            url=url,
            raw_html=html
        )

    def _extract_section(self, soup: BeautifulSoup, keywords: List[str]) -> str:
        """Extract a section from the page based on header keywords."""
        for keyword in keywords:
            # Try finding by id or class
            section = soup.find(id=re.compile(keyword, re.I))
            if not section:
                section = soup.find(class_=re.compile(keyword, re.I))

            # Try finding by header text
            if not section:
                for header in soup.find_all(['h2', 'h3', 'h4', 'div']):
                    if keyword.lower() in header.get_text().lower():
                        section = header.find_next_sibling()
                        if not section:
                            section = header.parent
                        break

            if section:
                # Get text content, cleaning up whitespace
                text = section.get_text(separator='\n', strip=True)
                # Remove excessive newlines
                text = re.sub(r'\n{3,}', '\n\n', text)
                return text[:5000]  # Limit length

        return ""

    async def scrape_ios_xr_advisories(self, limit: int = 50) -> List[ScrapedAdvisory]:
        """Scrape advisories specifically for IOS-XR."""
        listing = await self.get_advisory_listing(product="IOS XR", limit=limit)

        advisories = []
        for item in listing:
            if item.get("advisory_id"):
                advisory = await self.get_advisory_details(item["advisory_id"])
                if advisory:
                    advisories.append(advisory)
                await asyncio.sleep(0.5)  # Rate limiting

        return advisories

    async def scrape_ios_xe_advisories(self, limit: int = 50) -> List[ScrapedAdvisory]:
        """Scrape advisories specifically for IOS-XE."""
        listing = await self.get_advisory_listing(product="IOS XE", limit=limit)

        advisories = []
        for item in listing:
            if item.get("advisory_id"):
                advisory = await self.get_advisory_details(item["advisory_id"])
                if advisory:
                    advisories.append(advisory)
                await asyncio.sleep(0.5)  # Rate limiting

        return advisories

    async def scrape_critical_advisories(self, limit: int = 20) -> List[ScrapedAdvisory]:
        """Scrape critical severity advisories."""
        listing = await self.get_advisory_listing(severity="critical", limit=limit)

        advisories = []
        for item in listing:
            if item.get("advisory_id"):
                advisory = await self.get_advisory_details(item["advisory_id"])
                if advisory:
                    advisories.append(advisory)
                await asyncio.sleep(0.5)  # Rate limiting

        return advisories


# Synchronous wrapper
class CiscoAdvisoryScraperSync:
    """Synchronous wrapper for CiscoAdvisoryScraper."""

    def __init__(self):
        self._async_scraper = CiscoAdvisoryScraper()

    def _run(self, coro):
        """Run async coroutine synchronously."""
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        return loop.run_until_complete(coro)

    def get_advisory_details(self, advisory_id: str) -> Optional[ScrapedAdvisory]:
        return self._run(self._async_scraper.get_advisory_details(advisory_id))

    def scrape_ios_xr_advisories(self, limit: int = 50) -> List[ScrapedAdvisory]:
        return self._run(self._async_scraper.scrape_ios_xr_advisories(limit))

    def scrape_ios_xe_advisories(self, limit: int = 50) -> List[ScrapedAdvisory]:
        return self._run(self._async_scraper.scrape_ios_xe_advisories(limit))

    def scrape_critical_advisories(self, limit: int = 20) -> List[ScrapedAdvisory]:
        return self._run(self._async_scraper.scrape_critical_advisories(limit))
