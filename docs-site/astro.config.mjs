import { defineConfig } from "astro/config";
import sitemap from "@astrojs/sitemap";
import starlight from "@astrojs/starlight";

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
          items: [
            { autogenerate: { directory: "generated" } }
          ]
        },
        {
          label: "API",
          items: [
            { autogenerate: { directory: "api" } }
          ]
        },
        {
          label: "Reference",
          items: [
            { autogenerate: { directory: "reference" } }
          ]
        }
      ]
    }),
    sitemap()
  ]
});
