import numpy as np
import skfuzzy as fuzz
from skfuzzy import control as ctrl

def setup_fuzzy_system():
    """Sets up the fuzzy logic variables, membership functions, and rules."""
    # Antecedents (Inputs)
    traffic = ctrl.Antecedent(np.arange(0, 1001, 1), 'traffic')
    logins = ctrl.Antecedent(np.arange(0, 51, 1), 'logins')
    
    # Consequent (Output)
    risk = ctrl.Consequent(np.arange(0, 101, 1), 'risk')

    # Membership functions
    traffic['low'] = fuzz.trimf(traffic.universe, [0, 0, 400])
    traffic['medium'] = fuzz.trimf(traffic.universe, [200, 500, 800])
    traffic['high'] = fuzz.trimf(traffic.universe, [600, 1000, 1000])

    logins['low'] = fuzz.trimf(logins.universe, [0, 0, 20])
    logins['medium'] = fuzz.trimf(logins.universe, [10, 25, 40])
    logins['high'] = fuzz.trimf(logins.universe, [30, 50, 50])

    risk['low'] = fuzz.trimf(risk.universe, [0, 0, 40])
    risk['medium'] = fuzz.trimf(risk.universe, [20, 50, 80])
    risk['high'] = fuzz.trimf(risk.universe, [60, 100, 100])

    # Rules
    rule1 = ctrl.Rule(traffic['low'] & logins['low'], risk['low'])
    rule2 = ctrl.Rule(traffic['medium'] & logins['low'], risk['low'])
    rule3 = ctrl.Rule(traffic['low'] & logins['medium'], risk['medium'])
    rule4 = ctrl.Rule(traffic['medium'] & logins['medium'], risk['medium'])
    rule5 = ctrl.Rule(traffic['high'] | logins['high'], risk['high'])
    
    # Ensuring completeness
    rule6 = ctrl.Rule(traffic['low'] & logins['high'], risk['high'])
    rule7 = ctrl.Rule(traffic['high'] & logins['low'], risk['medium'])
    rule8 = ctrl.Rule(traffic['high'] & logins['medium'], risk['high'])
    rule9 = ctrl.Rule(traffic['medium'] & logins['high'], risk['high'])

    # Control System
    risk_ctrl = ctrl.ControlSystem([rule1, rule2, rule3, rule4, rule5, rule6, rule7, rule8, rule9])
    risk_sim = ctrl.ControlSystemSimulation(risk_ctrl)
    
    return traffic, logins, risk, risk_sim

# Initialize the system globally so it's ready to use
traffic_var, logins_var, risk_var, risk_sim = setup_fuzzy_system()

def evaluate_risk(traffic_val, logins_val):
    """
    Evaluates the risk level based on traffic and failed logins.
    Returns the computed risk percentage (0 to 100).
    """
    try:
        risk_sim.input['traffic'] = max(0, min(1000, traffic_val))
        risk_sim.input['logins'] = max(0, min(50, logins_val))
        risk_sim.compute()
        return risk_sim.output['risk']
    except Exception as e:
        print(f"Error computing risk: {e}")
        return 0.0

def get_membership_graphs():
    """
    Returns the antecendent and consequent variables to plot their membership functions
    or active membership.
    """
    return traffic_var, logins_var, risk_var
