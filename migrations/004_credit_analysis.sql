-- Credit Analysis table for AIBANK
-- Stores credit decisions, limits, and simulation history

CREATE TABLE IF NOT EXISTS credit_analysis (
  id SERIAL PRIMARY KEY,
  customer_id VARCHAR(255) NOT NULL,
  score INTEGER NOT NULL DEFAULT 500,
  probability_of_default FLOAT NOT NULL DEFAULT 0.5,
  decision VARCHAR(50) NOT NULL DEFAULT 'NOT_STARTED',
  approved_limit NUMERIC(15,2) DEFAULT 0,
  available_limit NUMERIC(15,2) DEFAULT 0,
  reasons JSONB DEFAULT '[]',
  lstm_risk_score FLOAT,
  scorecard_score INTEGER,
  model_version VARCHAR(100),
  analyzed_at TIMESTAMP DEFAULT NOW(),
  expires_at TIMESTAMP,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_credit_analysis_customer ON credit_analysis(customer_id);
CREATE INDEX IF NOT EXISTS idx_credit_analysis_status ON credit_analysis(decision);
CREATE INDEX IF NOT EXISTS idx_credit_analysis_analyzed ON credit_analysis(analyzed_at DESC);

-- Credit simulation history
CREATE TABLE IF NOT EXISTS credit_simulations (
  id SERIAL PRIMARY KEY,
  customer_id VARCHAR(255) NOT NULL,
  amount NUMERIC(15,2) NOT NULL,
  installments INTEGER NOT NULL,
  monthly_rate NUMERIC(8,6) NOT NULL,
  installment_value NUMERIC(15,2) NOT NULL,
  total_cost NUMERIC(15,2) NOT NULL,
  total_interest NUMERIC(15,2) NOT NULL,
  effective_annual_rate NUMERIC(8,4) NOT NULL,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_credit_sim_customer ON credit_simulations(customer_id);

-- View for latest analysis per customer
CREATE OR REPLACE VIEW v_latest_credit_analysis AS
SELECT DISTINCT ON (customer_id)
  id,
  customer_id,
  score,
  probability_of_default,
  decision,
  approved_limit,
  available_limit,
  reasons,
  lstm_risk_score,
  scorecard_score,
  model_version,
  analyzed_at,
  expires_at,
  created_at
FROM credit_analysis
ORDER BY customer_id, analyzed_at DESC;
