goog.require('goog.testing.asserts');
goog.require('goog.testing.jsunit');

function testPrincipalToBytes() {
    assertEquals(principalToBytes32("k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae"), "0x1db56bf994b37ae8e79f5ce000be1727a6060ae4eef24736b7cc999c3c020000");
    assertEquals(principalToBytes32("opspt-7okml-4664d-lqdny-uuuto-6nars-7am7t-jebvm-j3xj2-j4tdu-vqe"), "0x1dca62f9ef706b80db8a5293779a08cbe067e69206ac4eee9d27931d2b020000");
    assertEquals(principalToBytes32("ezu3d-2mifu-k3bh4-oqhrj-mbrql-5p67r-pp6pr-dbfra-unkx5-sxdtv-rae"), "0x1d882d15b09f8e81e29606305f5fefc5eff3e2309620a3557ecae39d62020000");
    assertEquals(principalToBytes32("47gy6-2c22d-voqoy-eflbe-gwml3-zwe52-r6lx7-rexro-ebluo-2rqcd-sae"), "0x1d5ad0eae83b042ac243598bde6c4eea3e5dff125e2e2057476a3010e4020000");
    assertEquals(principalToBytes32("2chl6-4hpzw-vqaaa-aaaaa-c"), "0x09efcdab00000000000100000000000000000000000000000000000000000000");
}