from model.security_risk import SecurityRisk


def test_dont_parse_risk():
    assert SecurityRisk.of(None) is None
    assert SecurityRisk.of('') is None
    assert SecurityRisk.of(' ') is None
    assert SecurityRisk.of('no idea')  is None
    assert SecurityRisk.of('todo') is None
    assert SecurityRisk.of(';') is None
    assert SecurityRisk.of('high:') is None

def test_parse_risk_from_full_risk():
    assert SecurityRisk.of('informational') == SecurityRisk.INFORMATIONAL
    assert SecurityRisk.of('  LOW') == SecurityRisk.LOW
    assert SecurityRisk.of('medIUM  ') == SecurityRisk.MEDIUM
    assert SecurityRisk.of(' high   ') == SecurityRisk.HIGH
    assert SecurityRisk.of('  CRITICAL   ') == SecurityRisk.CRITICAL

def test_parse_risk_from_partial_risk():
    assert SecurityRisk.of('info   ') == SecurityRisk.INFORMATIONAL
    assert SecurityRisk.of(' lo  ') == SecurityRisk.LOW
    assert SecurityRisk.of('  MEDI') == SecurityRisk.MEDIUM
    assert SecurityRisk.of('  hI   ') == SecurityRisk.HIGH
    assert SecurityRisk.of('crit') == SecurityRisk.CRITICAL

def test_new_risk_from():
    assert SecurityRisk.new_risk_from(SecurityRisk.INFORMATIONAL, SecurityRisk.LOW) == SecurityRisk.LOW
    assert SecurityRisk.new_risk_from(SecurityRisk.MEDIUM, SecurityRisk.LOW) == SecurityRisk.MEDIUM
    assert SecurityRisk.new_risk_from(SecurityRisk.HIGH, SecurityRisk.HIGH) == SecurityRisk.HIGH
    assert SecurityRisk.new_risk_from(SecurityRisk.MEDIUM, SecurityRisk.CRITICAL) == SecurityRisk.CRITICAL
    assert SecurityRisk.new_risk_from(None, SecurityRisk.CRITICAL) is None
    assert SecurityRisk.new_risk_from(None, SecurityRisk.HIGH) is None
    assert SecurityRisk.new_risk_from(SecurityRisk.MEDIUM, None) is None
    assert SecurityRisk.new_risk_from(SecurityRisk.LOW, None) is None
    assert SecurityRisk.new_risk_from(SecurityRisk.INFORMATIONAL, None) is None
