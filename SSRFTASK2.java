/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.ssrf;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"ssrf.hint3"})
public class SSRFTask2 implements AssignmentEndpoint {

  private static final String ALLOWED_HOST = "ifconfig.pro";

  @PostMapping("/SSRF/task2")
  @ResponseBody
  public AttackResult completed(@RequestParam String url) {
    return furBall(url);
  }

  protected AttackResult furBall(String rawUrl) {
    final String catHtml = "<img class=\"image\" alt=\"image post\" src=\"images/cat.jpg\">";
    final String downMsg = "<html><body>Although the http://ifconfig.pro site is down, you still "
        + "managed to solve this exercise the right way!</body></html>";
    try {
      URI uri = URI.create(rawUrl.trim());

      String scheme = uri.getScheme();
      if (scheme == null || !(scheme.equalsIgnoreCase("http") || scheme.equalsIgnoreCase("https"))) {
        return getFailedResult(catHtml);
      }

      if (uri.getUserInfo() != null) return getFailedResult(catHtml);
      String host = uri.getHost();
      if (!ALLOWED_HOST.equalsIgnoreCase(host)) return getFailedResult(catHtml);

      int port = uri.getPort();
      int expected = scheme.equalsIgnoreCase("https") ? 443 : 80;
      if (port != -1 && port != expected) return getFailedResult(catHtml);
      String path = uri.getPath();
      if (path != null && !path.isBlank() && !"/".equals(path)) return getFailedResult(catHtml);

      for (InetAddress a : InetAddress.getAllByName(host)) {
        if (a.isAnyLocalAddress() || a.isLoopbackAddress() || a.isLinkLocalAddress()
            || a.isSiteLocalAddress() || a.isMulticastAddress()) {
          return getFailedResult(catHtml);
        }
      }

      HttpURLConnection conn = (HttpURLConnection) new URL(uri.toString()).openConnection();
      conn.setInstanceFollowRedirects(false);
      conn.setConnectTimeout(3000);
      conn.setReadTimeout(3000);
      conn.setRequestMethod("GET");

      int code = conn.getResponseCode();
      if (code >= 300 && code < 400) return getFailedResult(catHtml); 

      try (InputStream in = conn.getInputStream()) {
        String html = new String(in.readAllBytes(), StandardCharsets.UTF_8).replace("\n", "<br>");
        return success(this).feedback("ssrf.success").output(html).build();
      }
    } catch (IOException e) {
      return success(this).feedback("ssrf.success").output(downMsg).build();
    } catch (RuntimeException e) {
      return getFailedResult(catHtml);
    }
  }

  private AttackResult getFailedResult(String errorMsg) {
    return failed(this).feedback("ssrf.failure").output(errorMsg).build();
  }
}
