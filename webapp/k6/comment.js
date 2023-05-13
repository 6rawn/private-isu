import http, { post } from "k6/http";

import { check } from "k6";

import { parseHTML } from "k6/html";

import { url } from "./config.js";
import { getAccount } from "./account.js";

export default function () {
  const account = getAccount()

  const loginRes = http.post(url("/login"), {
    account_name: account.account_name,
    password: account.password
  });
  check(loginRes, {
    "is status 200": (r) => r.status === 200,
  });

  const res = http.get(url("/@terra"));

  const doc = parseHTML(res.body);

  const token = doc.find('input[name="csrf_token"]').first().attr("value");
  const postId = doc.find('input[name="post_id"]').first().attr("value");

  const commentRes = http.post(url("/comment"), {
    post_id: postId,
    csrf_token: token,
    comment: "Hello k6!",
  });
  check(commentRes, {
    "is status 200": (r) => r.status === 200,
  });
}
