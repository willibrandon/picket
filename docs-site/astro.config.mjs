import { defineConfig } from "astro/config";
import sitemap from "@astrojs/sitemap";
import starlight from "@astrojs/starlight";

const projectDocsSidebar = [
  { label: "Picket Design", slug: "generated/design" },
  { label: "Rule Authoring", slug: "generated/rules" },
  { label: "Randomness Scoring", slug: "generated/randomness" },
  { label: "Reports", slug: "generated/reports" },
  { label: "Validation and Privacy", slug: "generated/validation" },
  { label: "Native Scan Cache", slug: "generated/cache" },
  { label: "Performance", slug: "generated/performance" },
  { label: "Embedding Picket", slug: "generated/embedding" },
  { label: "GitHub Action", slug: "generated/action" },
  { label: "Azure DevOps", slug: "generated/azure-devops" },
  { label: "GitHub", slug: "generated/github" },
  { label: "GitLab", slug: "generated/gitlab" },
  { label: "Gitea", slug: "generated/gitea" },
  { label: "Bitbucket", slug: "generated/bitbucket" },
  { label: "Object Stores", slug: "generated/object-stores" },
  { label: "Container Images", slug: "generated/containers" },
  { label: "Git Hooks", slug: "generated/hooks" },
  { label: "Terminal UI", slug: "generated/tui" },
  { label: "Marketplaces", slug: "generated/marketplaces" },
  { label: "Release Profiles", slug: "generated/release" },
  { label: "Picket Compatibility Ledger", slug: "generated/parity" },
  { label: "Upstream Pins", slug: "generated/upstream" }
];

const apiSidebar = [
  { label: "Picket.Compat API", slug: "api/picket-compat" },
  { label: "Picket.Engine API", slug: "api/picket-engine" },
  { label: "Picket.Report API", slug: "api/picket-report" },
  { label: "Picket.Rules API", slug: "api/picket-rules" },
  { label: "Picket.Security API", slug: "api/picket-security" }
];

const referenceSidebar = [
  { label: "CLI Reference", slug: "reference/cli" },
  { label: "Config Schema Reference", slug: "reference/config-schema" },
  { label: "Rule Catalog", slug: "reference/rule-catalog" },
  { label: "Report Schema Reference", slug: "reference/report-schemas" },
  { label: "Validation and Analyze Reference", slug: "reference/validation-analyze" },
  { label: "GitHub Action Reference", slug: "reference/github-action" },
  { label: "Azure DevOps Task Reference", slug: "reference/azure-devops-task" },
  { label: "Release Profile Reference", slug: "reference/release-profiles" }
];

export default defineConfig({
  site: "https://willibrandon.github.io",
  base: "/picket",
  trailingSlash: "always",
  integrations: [
    starlight({
      title: "Picket",
      description: "Gitleaks-compatible, Scout-powered .NET secrets scanner.",
      customCss: ["./src/styles/docs.css"],
      social: [
        {
          icon: "github",
          label: "GitHub",
          href: "https://github.com/willibrandon/picket"
        }
      ],
      sidebar: [
        {
          label: "Start",
          items: [
            { label: "Overview", slug: "" }
          ]
        },
        {
          label: "Project Docs",
          items: projectDocsSidebar
        },
        {
          label: "API",
          items: apiSidebar
        },
        {
          label: "Reference",
          items: referenceSidebar
        }
      ]
    }),
    sitemap()
  ]
});
