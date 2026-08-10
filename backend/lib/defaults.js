import { ROLES } from "./config.js";

export const SITE = {
  name: "StrikeUp Store",
  tagline: "Apps built by Khan — browse, discover and download.",
  about:
    "StrikeUp Store is the official home of apps built by Khan — starting with Strike Up, " +
    "Pakistan's home of real-money mobile esports. Everything here is published directly " +
    "by the developer, with fast direct APK downloads and no third-party stores in between.",
  heroTitle:
    "One home for\nall of Khan's apps.",
  heroSub:
    "Apps built by Khan — browse, discover and download. No stores in between — every APK is served straight from the developer.",
  // Ads — "dummy" renders branded placeholder boxes everywhere (no account needed),
  // "adsense" loads real Google AdSense units. Test ids are Google's official ones.
  adsEnabled: true,
  adMode: "dummy",
  adClient: "ca-pub-3940256099942544",
  adSlotLeaderboard: "6300978111", // Fixed Sized Banner test unit
  adSlotNative: "2247696110", // Native test unit (in-feed cards)
  adSlotDetail: "9257395921", // App open test unit (shows up top of an app page)
  adSlotInterstitial: "1033173712", // Interstitial test unit (wide banner on the homepage)
  adSlotSticky: "9214589741", // Anchored Adaptive Banner test unit (mobile footer)
  terms:
    "## Terms & Conditions\n\nBy downloading apps from this site you agree that:\n\n" +
    "- All software is provided \"as is\", without warranty of any kind.\n" +
    "- Apps are published directly by the developer, who is responsible for their content.\n" +
    "- You download and install apps at your own risk.\n" +
    "- Unauthorized copying, redistribution or modification of the apps is prohibited.\n\n" +
    "We may update these terms at any time; continued use of the site means you accept the current version.\n\n" +
    "_Last updated automatically by the site owner._",
  privacy:
    "## Privacy Policy\n\nWe keep things simple and private:\n\n" +
    "- No account is required to browse or download apps.\n" +
    "- Anonymous review submissions include only the name you choose (if any).\n" +
    "- Standard server logs (IP, user agent) are used only to protect the service and count downloads.\n" +
    "- We do not sell or share personal data with third parties.\n" +
    "- Advertising uses Google AdSense — see Google's own privacy policy for how it uses cookies.\n\n" +
    "Questions? Contact the site owner from the Contact section.\n\n" +
    "_Last updated automatically by the site owner._"
};

export const SEED_CATEGORIES = [
  { id: "cat-gaming", name: "Gaming Utilities", slug: "gaming-utilities", color: "#a855f7" },
  { id: "cat-tools", name: "Editing Tools", slug: "editing-tools", color: "#38bdf8" },
  { id: "cat-productivity", name: "Productivity", slug: "productivity", color: "#34d399" }
];

export const SEED_APPS = [
  {
    id: "app-strike-up",
    name: "Strike Up",
    slug: "strike-up",
    tagline: "Pakistan's home of real-money mobile esports.",
    description:
      "# Strike Up\n\nCompete in **Free Fire & PUBG tournaments** with verified results and PKR payouts — straight to Easypaisa, JazzCash or your bank.\n\n## What's inside\n\n- Live tournaments with real prize pools\n- Verified wallet system with human-reviewed payouts\n- Withdrawals processed in under 24 hours\n- Rank & level system from G Rookie to SSS Legend\n- Free and paid entry formats\n\n> Android only for v1 — iOS is on the way.",
    categoryId: "cat-gaming",
    iconUrl: "",
    screenshots: [],
    apkUrl: "",
    version: "1.3.0",
    changelog: "v1.3.0 — Light & dark themes, a cleaner design, and a faster mobile experience.",
    minAndroid: "Android 7.0+",
    fileSizeMb: null,
    status: "published",
    featured: true,
    featuredOrder: 1,
    downloadCount: 0,
    viewCount: 0,
    createdAt: null,
    updatedAt: null
  }
];

export { ROLES };
