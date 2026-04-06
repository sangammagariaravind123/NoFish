import { addTemporaryAllow } from "../lib/controls.js";
import { recordWarningBypass } from "../lib/history.js";

const urlParams = new URLSearchParams(window.location.search);
const originalUrl = urlParams.get("url");
const trust = urlParams.get("trust");
const reason = urlParams.get("reason");

document.getElementById("trust").innerText = trust || "0";
if (reason) {
  const reasonNode = document.getElementById("reason");
  const strongNode = document.createElement("strong");
  strongNode.textContent = "Why: ";
  reasonNode.replaceChildren(strongNode, document.createTextNode(reason));
} else {
  document.getElementById("reason").style.display = "none";
}

document.getElementById("back").onclick = () => history.back();
document.getElementById("proceed").onclick = async () => {
  if (originalUrl) {
    await addTemporaryAllow(originalUrl);
    await recordWarningBypass(originalUrl);
    window.location.href = originalUrl;
  }
};
