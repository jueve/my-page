import lume from "lume/mod.ts";
import date from "lume/plugins/date.ts";
import basePath from "lume/plugins/base_path.ts";

const site = lume({
    location: new URL("https://cashitsuki.com"),
    cwd: Deno.cwd(),
    src: "src",
    prettyUrls: true,
    dest: "_site",
});

site.ignore("README.md")
    .ignore("check.sh")
    .ignore("build.sh")
    .use(basePath())
    .use(date());

site.copy("img")
    .copy("favicon.ico")
    .copy("404.html");

export default site;
