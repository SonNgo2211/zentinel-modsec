//! Transaction processing for ModSecurity.

use std::sync::Arc;

use super::chain::ChainState;
use super::intervention::Intervention;
use super::phase::Phase;
use super::ruleset::{CompiledRule, CompiledRuleset, RuleEngineMode};
use super::scoring::AnomalyScore;
use crate::actions::{execute_actions, DisruptiveOutcome, FlowOutcome, SetVarOp, SetVarOperation};
use crate::error::Result;
use crate::parser::VariableName;
use crate::variables::{RequestData, ResponseData, TxCollection, VariableResolver};

/// A ModSecurity transaction for processing a single request.
pub struct Transaction {
    /// Compiled ruleset reference.
    ruleset: Arc<CompiledRuleset>,
    /// Request data.
    request: RequestData,
    /// Response data.
    response: ResponseData,
    /// TX collection (mutable variables).
    tx: TxCollection,
    /// Current phase.
    phase: Phase,
    /// Intervention (if any).
    intervention: Option<Intervention>,
    /// Anomaly score tracker.
    anomaly_score: AnomalyScore,
    /// Default block status.
    default_status: u16,
    /// Matched rules.
    matched_rules: Vec<String>,
    /// Allow flag (skip further processing).
    allowed: bool,
    /// Matched variables for current rule evaluation.
    matched_vars: Vec<(String, String)>,
    /// Regex captures from last match.
    captures: Vec<String>,
}

impl Transaction {
    /// Create a new transaction.
    pub fn new(ruleset: Arc<CompiledRuleset>, default_status: u16) -> Self {
        Self {
            ruleset,
            request: RequestData::new(),
            response: ResponseData::new(),
            tx: TxCollection::new(),
            phase: Phase::RequestHeaders,
            intervention: None,
            anomaly_score: AnomalyScore::new(),
            default_status,
            matched_rules: Vec::new(),
            allowed: false,
            matched_vars: Vec::new(),
            captures: Vec::new(),
        }
    }

    /// Process the request URI.
    pub fn process_uri(&mut self, uri: &str, method: &str, protocol: &str) -> Result<()> {
        self.request.set_uri(uri);
        self.request.set_method(method);
        self.request.set_protocol(protocol);
        Ok(())
    }

    /// Add a request header.
    pub fn add_request_header(&mut self, name: &str, value: &str) -> Result<()> {
        self.request.add_header(name, value);
        Ok(())
    }

    /// Process request headers (Phase 1).
    pub fn process_request_headers(&mut self) -> Result<()> {
        self.phase = Phase::RequestHeaders;
        self.run_phase(Phase::RequestHeaders)?;
        Ok(())
    }

    /// Append data to request body.
    pub fn append_request_body(&mut self, data: &[u8]) -> Result<()> {
        self.request.append_body(data);
        Ok(())
    }

    /// Process request body (Phase 2).
    pub fn process_request_body(&mut self) -> Result<()> {
        self.phase = Phase::RequestBody;
        self.request.parse_form_body();
        self.run_phase(Phase::RequestBody)?;
        Ok(())
    }

    /// Add a response header.
    pub fn add_response_header(&mut self, name: &str, value: &str) -> Result<()> {
        self.response.add_header(name, value);
        Ok(())
    }

    /// Process response headers (Phase 3).
    pub fn process_response_headers(&mut self) -> Result<()> {
        self.phase = Phase::ResponseHeaders;
        self.run_phase(Phase::ResponseHeaders)?;
        Ok(())
    }

    /// Append data to response body.
    pub fn append_response_body(&mut self, data: &[u8]) -> Result<()> {
        self.response.append_body(data);
        Ok(())
    }

    /// Process response body (Phase 4).
    pub fn process_response_body(&mut self) -> Result<()> {
        self.phase = Phase::ResponseBody;
        self.run_phase(Phase::ResponseBody)?;
        Ok(())
    }

    /// Process logging phase (Phase 5).
    pub fn process_logging(&mut self) -> Result<()> {
        self.phase = Phase::Logging;
        self.run_phase(Phase::Logging)?;
        Ok(())
    }

    /// Get current intervention (if any).
    pub fn intervention(&self) -> Option<&Intervention> {
        self.intervention.as_ref()
    }

    /// Check if there's an intervention.
    pub fn has_intervention(&self) -> bool {
        self.intervention.is_some()
    }

    /// Get matched rule IDs.
    pub fn matched_rules(&self) -> &[String] {
        &self.matched_rules
    }

    /// Get the anomaly score.
    pub fn anomaly_score(&self) -> i32 {
        self.anomaly_score.inbound
    }

    /// Get the TX collection.
    pub fn tx(&self) -> &TxCollection {
        &self.tx
    }

    /// Get mutable TX collection.
    pub fn tx_mut(&mut self) -> &mut TxCollection {
        &mut self.tx
    }

    /// Run rules for a specific phase.
    fn run_phase(&mut self, phase: Phase) -> Result<()> {
        if self.allowed || self.intervention.is_some() {
            return Ok(());
        }

        if self.ruleset.engine_mode() == RuleEngineMode::Off {
            return Ok(());
        }

        // Clone rules to avoid borrow conflicts with mutable self
        let rules: Vec<CompiledRule> = self.ruleset.rules_for_phase(phase).to_vec();
        if rules.is_empty() {
            return Ok(());
        }

        let mut chain_state = ChainState::new();
        let mut skip_count: u32 = 0;
        let mut skip_after: Option<String> = None;

        let mut idx = 0;
        let mut current_chain_id: Option<String> = None;
        let mut current_chain_should_log = false;

        while idx < rules.len() {
            // Handle skip
            if skip_count > 0 {
                skip_count -= 1;
                idx += 1;
                continue;
            }

            // Handle skipAfter
            if let Some(ref marker) = skip_after {
                if let Some((marker_phase, marker_idx)) = self.ruleset.marker(marker) {
                    if marker_phase == phase && marker_idx > idx {
                        idx = marker_idx;
                        skip_after = None;
                        continue;
                    }
                }
                // Marker not found or in different phase, continue
                idx += 1;
                continue;
            }

            let rule = &rules[idx];

            // If we're starting a new chain (or a single rule), track the ID from the head
            if !chain_state.in_chain {
                current_chain_id = rule.id.clone();
                current_chain_should_log = false;
            }

            // Handle chain continuation
            if chain_state.in_chain && !rule.is_chain && rule.chain_next.is_none() {
                // End of chain, check if previous rules in chain matched
                if !chain_state.chain_matched {
                    chain_state.reset();
                    current_chain_id = None;
                    current_chain_should_log = false;
                    idx += 1;
                    continue;
                }
            }

            // Evaluate rule
            let (matched, matched_value, captures) = self.evaluate_rule(rule)?;

            if matched {
                // Execute actions
                let action_result =
                    crate::actions::execute_actions(&rule.actions, matched_value.as_deref(), &captures);

                // Determine if this rule match should trigger logging of the chain
                let is_strictly_blocking = matches!(
                    action_result.disruptive,
                    Some(DisruptiveOutcome::Deny(_))
                        | Some(DisruptiveOutcome::Drop)
                        | Some(DisruptiveOutcome::Redirect(_))
                );
                let causes_score_increment = action_result.setvar_ops.iter().any(|op| {
                    (op.name.to_lowercase().contains("score")
                        || op.collection.to_lowercase().contains("score"))
                        && matches!(op.operation, SetVarOperation::Increment(_))
                });

                if (is_strictly_blocking || causes_score_increment) && !action_result.metadata.no_log {
                    current_chain_should_log = true;
                }

                // If this is the end of a matching chain (or a single matching rule),
                // and we decided it should be logged, add the ID of the chain head.
                if !rule.is_chain {
                    if current_chain_should_log {
                        if let Some(id) = current_chain_id.take() {
                            self.matched_rules.push(id);
                        }
                    }
                    current_chain_should_log = false;
                    current_chain_id = None;
                }

                // Apply setvar operations
                for op in &action_result.setvar_ops {
                    self.apply_setvar(op, matched_value.as_deref(), None); // matched_var_name would need more tracking
                }

                // Handle flow control
                match action_result.flow {
                    FlowOutcome::Chain => {
                        if !chain_state.in_chain {
                            chain_state.start_chain(idx);
                        }
                        chain_state.continue_chain(true, &captures);
                    }
                    FlowOutcome::Skip(n) => {
                        skip_count = n;
                    }
                    FlowOutcome::SkipAfter(marker) => {
                        skip_after = Some(marker);
                    }
                    FlowOutcome::Continue => {}
                }

                // Handle disruptive action
                if let Some(outcome) = action_result.disruptive {
                    // Only apply if not in detection-only mode
                    let should_block = self.ruleset.engine_mode() == RuleEngineMode::On;

                    match outcome {
                        DisruptiveOutcome::Deny(status) => {
                            if should_block {
                                let mut intervention = Intervention::deny(status, phase, rule.id.clone());
                                intervention.add_metadata(action_result.metadata);
                                self.intervention = Some(intervention);
                                return Ok(());
                            }
                        }
                        DisruptiveOutcome::Block => {
                            if should_block {
                                let mut intervention = Intervention::deny(self.default_status, phase, rule.id.clone());
                                intervention.add_metadata(action_result.metadata);
                                self.intervention = Some(intervention);
                                return Ok(());
                            }
                        }
                        DisruptiveOutcome::Allow => {
                            self.allowed = true;
                            return Ok(());
                        }
                        DisruptiveOutcome::Redirect(url) => {
                            if should_block {
                                let mut intervention = Intervention::redirect(url, phase, rule.id.clone());
                                intervention.add_metadata(action_result.metadata);
                                self.intervention = Some(intervention);
                                return Ok(());
                            }
                        }
                        DisruptiveOutcome::Drop => {
                            if should_block {
                                let mut intervention = Intervention::drop(phase, rule.id.clone());
                                intervention.add_metadata(action_result.metadata);
                                self.intervention = Some(intervention);
                                return Ok(());
                            }
                        }
                        DisruptiveOutcome::Pass => {
                            // Continue processing
                        }
                    }
                }
            } else {
                // Rule didn't match
                if chain_state.in_chain {
                    chain_state.chain_matched = false;
                }
            }

            // End chain if this is the last rule in chain
            if chain_state.in_chain && !rule.is_chain {
                chain_state.end_chain();
            }

            idx += 1;
        }

        // Sync anomaly score to TX
        self.anomaly_score.sync_to_tx(&mut self.tx);

        Ok(())
    }

    /// Evaluate a single rule.
    fn evaluate_rule(&self, rule: &CompiledRule) -> Result<(bool, Option<String>, Vec<String>)> {
        let resolver = VariableResolver::new(
            &self.request,
            &self.response,
            &self.tx,
            None,
            &self.matched_vars,
            &self.captures,
        );

        // Resolve variables from all specs
        let mut all_values = Vec::new();
        if rule.variables.is_empty() {
            // SecAction or rule with no variables
            let transformed = rule.transformations.apply("");
            let result = rule.operator.execute(&transformed, Some(&self.tx));
            let final_match = if rule.operator_negated { !result.matched } else { result.matched };
            return Ok((final_match, Some(transformed.to_string()), result.captures));
        }

        for spec in &rule.variables {
            all_values.extend(resolver.resolve(spec));
        }

        if all_values.is_empty() {
            // Variables were specified but none were found (e.g. TX:foo where foo is missing)
            return Ok((false, None, Vec::new()));
        }

        // Apply transformations and match
        for (_name, value) in all_values {
            let transformed = rule.transformations.apply(&value);
            let result = rule.operator.execute(&transformed, Some(&self.tx));

            let final_match = if rule.operator_negated { !result.matched } else { result.matched };

            if final_match {
                return Ok((true, Some(transformed.to_string()), result.captures));
            }
        }

        Ok((false, None, Vec::new()))
    }

    /// Apply a setvar operation.
    fn apply_setvar(&mut self, op: &crate::actions::SetVarOp, matched_var: Option<&str>, matched_var_name: Option<&str>) {
        crate::actions::apply_setvar(&mut self.tx, op, matched_var, matched_var_name);

        // Sync anomaly score from TX if relevant
        if op.name == "anomaly_score" {
            self.anomaly_score.sync_from_tx(&self.tx);
        }
    }
}

impl std::fmt::Debug for Transaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Transaction")
            .field("phase", &self.phase)
            .field("has_intervention", &self.intervention.is_some())
            .field("anomaly_score", &self.anomaly_score.inbound)
            .field("matched_rules", &self.matched_rules)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::variables::Collection;

    fn make_ruleset(rules: &str) -> Arc<CompiledRuleset> {
        Arc::new(CompiledRuleset::from_string(rules).unwrap())
    }

    #[test]
    fn test_basic_match() {
        let ruleset = make_ruleset(r#"
            SecRule REQUEST_URI "@contains /admin" "id:1,phase:1,deny"
        "#);
        let mut tx = Transaction::new(ruleset, 403);
        tx.process_uri("/admin/dashboard", "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();

        assert!(tx.has_intervention());
        let intervention = tx.intervention().unwrap();
        assert_eq!(intervention.status, 403);
    }

    #[test]
    fn test_no_match() {
        let ruleset = make_ruleset(r#"
            SecRule REQUEST_URI "@contains /admin" "id:1,phase:1,deny"
        "#);
        let mut tx = Transaction::new(ruleset, 403);
        tx.process_uri("/public/index.html", "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();

        assert!(!tx.has_intervention());
    }

    #[test]
    fn test_setvar() {
        let ruleset = make_ruleset(r#"
            SecRule REQUEST_URI "@contains /test" "id:1,phase:1,pass,setvar:TX.score=5"
        "#);
        let mut tx = Transaction::new(ruleset, 403);
        tx.process_uri("/test/page", "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();

        assert!(!tx.has_intervention());
        let score = tx.tx().get("score").and_then(|v| v.first().map(|s| s.to_string()));
        assert_eq!(score, Some("5".to_string()));
    }

    #[test]
    fn test_detection_only_mode() {
        let ruleset = make_ruleset(r#"
            SecRuleEngine DetectionOnly
            SecRule REQUEST_URI "@contains /admin" "id:1,phase:1,deny"
        "#);
        let mut tx = Transaction::new(Arc::new(
            CompiledRuleset::from_string(r#"
                SecRuleEngine DetectionOnly
                SecRule REQUEST_URI "@contains /admin" "id:1,phase:1,deny"
            "#).unwrap()
        ), 403);
        tx.process_uri("/admin/dashboard", "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();

        // Should match but not block
        assert!(!tx.has_intervention());
        assert!(tx.matched_rules().contains(&"1".to_string()));
    }

    #[test]
    fn test_matched_rules_filtering() {
        let ruleset = make_ruleset(r#"
            SecRule REQUEST_URI "@contains /init" "id:901000,phase:1,pass,nolog,msg:'Initialization rule'"
            SecRule REQUEST_URI "@contains /score" "id:942100,phase:1,pass,nolog,setvar:TX.anomaly_score=+5"
            SecRule REQUEST_URI "@contains /block" "id:949110,phase:1,deny,status:403,msg:'Blocking rule'"
            SecRule REQUEST_URI "@contains /chain" "id:950000,phase:1,pass,chain"
              SecRule REQUEST_URI "@contains /chain" "phase:1,setvar:TX.anomaly_score=+1"
            SecRule REQUEST_URI "@contains /nolog" "id:960000,phase:1,deny,nolog"
        "#);

        // Test initialization rule (should match but NOT be in matched_rules due to no-score/no-block)
        let mut tx1 = Transaction::new(ruleset.clone(), 403);
        tx1.process_uri("/init", "GET", "HTTP/1.1").unwrap();
        tx1.process_request_headers().unwrap();
        assert!(!tx1.matched_rules().contains(&"901000".to_string()), "Initialization rule should NOT be logged");

        // Test scoring rule (should be in matched_rules even if it has nolog, wait... no)
        // Actually, if it has nolog, it should be excluded. 
        // In the ruleset string above, id 942100 has nolog. 
        let mut tx2 = Transaction::new(ruleset.clone(), 403);
        tx2.process_uri("/score", "GET", "HTTP/1.1").unwrap();
        tx2.process_request_headers().unwrap();
        assert!(!tx2.matched_rules().contains(&"942100".to_string()), "Rule with nolog should NOT be logged");

        // Test blocking rule (should be in matched_rules)
        let mut tx3 = Transaction::new(ruleset.clone(), 403);
        tx3.process_uri("/block", "GET", "HTTP/1.1").unwrap();
        tx3.process_request_headers().unwrap();
        assert!(tx3.matched_rules().contains(&"949110".to_string()), "Blocking rule SHOULD be logged");

        // Test chain rule (id 950000 should be logged because the chain increments score)
        let mut tx4 = Transaction::new(ruleset.clone(), 403);
        tx4.process_uri("/chain", "GET", "HTTP/1.1").unwrap();
        tx4.process_request_headers().unwrap();
        assert!(tx4.matched_rules().contains(&"950000".to_string()), "Chain head ID SHOULD be logged for matching chain");

        // Test multiple matches in one transaction
        // /init matches 901000 (nolog)
        // /block matches 949110 (log)
        // Only 949110 should be in matched_rules
        let mut tx6 = Transaction::new(ruleset.clone(), 403);
        tx6.process_uri("/init/block", "GET", "HTTP/1.1").unwrap(); // This URI matches BOTH rules
        tx6.process_request_headers().unwrap();
        assert!(!tx6.matched_rules().contains(&"901000".to_string()), "Initialization rule should NOT be logged even with another match");
        assert!(tx6.matched_rules().contains(&"949110".to_string()), "Blocking rule SHOULD be logged");
        assert_eq!(tx6.matched_rules().len(), 1, "There should be EXACTLY one matched rule");
    }
}
