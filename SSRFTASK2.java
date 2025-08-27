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
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({ "ssrf.hint3" })
public class SSRFTask2 implements AssignmentEndpoint {

  @PostMapping("/SSRF/task2")
  public AttackResult completed(@RequestParam("url") String userUrl) {
    // 1) Validar e RECONSTRUIR a URL com host/esquema fixos (quebra o fluxo de taint).
    try {
      URI in = new URI(userUrl.trim());
      if (!"https".equalsIgnoreCase(in.getScheme()) || !"ifconfig.pro".equalsIgnoreCase(in.getHost())) {
        return getFailedResult("<img class=\"image\" alt=\"image post\" src=\"images/cat.jpg\">");
      }
      String path = (in.getRawPath() == null || in.getRawPath().isBlank()) ? "/" : in.getRawPath();
      String q = in.getRawQuery();
      String pathAndQuery = (q == null) ? path : path + "?" + q;

      URL safe = new URL("https", "ifconfig.pro", pathAndQuery); // alvo constante
      return furBall(safe);

    } catch (URISyntaxException | MalformedURLException e) {
      return getFailedResult("<img class=\"image\" alt=\"image post\" src=\"images/cat.jpg\">");
    }
  }

  private AttackResult furBall(URL safeUrl) {
    try {
      HttpURLConnection conn = (HttpURLConnection) safeUrl.openConnection();
      conn.setInstanceFollowRedirects(false); // sem redirects
      conn.setConnectTimeout(5000);
      conn.setReadTimeout(5000);

      try (InputStream in = conn.getInputStream()) {
        String html = new String(in.readAllBytes(), StandardCharsets.UTF_8).replace("\n", "<br>");
        return success(this).feedback("ssrf.success").output(html).build();
      }
    } catch (IOException e) {
      String html = "<html><body>Mesmo que o site alvo esteja indisponível, sua proteção contra SSRF está ativa.</body></html>";
      return success(this).feedback("ssrf.success").output(html).build();
    }
  }

  private AttackResult getFailedResult(String errorMsg) {
    return failed(this).feedback("ssrf.failure").output(errorMsg).build();
  }
}
