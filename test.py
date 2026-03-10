from fuzzy_logic import evaluate_risk

print(f"Low Risk (50, 2): {evaluate_risk(50, 2):.2f}%")
print(f"Medium Risk (500, 25): {evaluate_risk(500, 25):.2f}%")
print(f"High Risk (900, 45): {evaluate_risk(900, 45):.2f}%")
