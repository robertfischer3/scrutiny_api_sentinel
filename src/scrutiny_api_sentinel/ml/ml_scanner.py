"""
Machine Learning Scanner Module

This module extends the base Scanner with machine learning capabilities
to detect anomalies, security threats, and performance issues in API traffic.
"""

import logging
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union, Tuple
from pathlib import Path
import pickle
import json
import asyncio

from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.cluster import DBSCAN
from sklearn.model_selection import train_test_split
from joblib import dump, load

from ..scanner.base import Scanner
from ..scanner.models import APILogEntry, ScanResult

logger = logging.getLogger("api-sentinel.ml-scanner")

class MLScanner(Scanner):
    """
    Scanner that uses machine learning to detect anomalies and threats.
    Extends the base Scanner with ML-based detection capabilities.
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the ML scanner with configuration options.
        
        Args:
            config: Dictionary of configuration parameters
        """
        super().__init__(config)
        self.models = {}
        self.feature_extractors = {}
        self.scaler = StandardScaler()
        self.model_dir = Path(self.config.get("model_dir", "models"))
        self.model_dir.mkdir(exist_ok=True)
        
        # Initialize models if available
        self._load_models()
        
        logger.info(f"Initialized MLScanner with {len(self.models)} models")
    
    def _load_models(self):
        """Load machine learning models from disk if available."""
        model_types = ["anomaly_detector", "security_classifier", "performance_predictor"]
        
        for model_type in model_types:
            model_path = self.model_dir / f"{model_type}.joblib"
            if model_path.exists():
                try:
                    self.models[model_type] = load(model_path)
                    logger.info(f"Loaded {model_type} model from {model_path}")
                except Exception as e:
                    logger.error(f"Error loading {model_type} model: {str(e)}")
    
    def _save_model(self, model_type: str):
        """Save a model to disk."""
        if model_type in self.models:
            model_path = self.model_dir / f"{model_type}.joblib"
            try:
                dump(self.models[model_type], model_path)
                logger.info(f"Saved {model_type} model to {model_path}")
            except Exception as e:
                logger.error(f"Error saving {model_type} model: {str(e)}")
    
    def _extract_features(self, entries: List[APILogEntry]) -> Tuple[pd.DataFrame, List[str]]:
        """
        Extract features from API log entries for machine learning.
        
        Args:
            entries: List of API log entries
            
        Returns:
            Tuple of (DataFrame with features, list of feature names)
        """
        # Convert entries to a DataFrame for easier processing
        data = []
        for entry in entries:
            record = {
                "timestamp": entry.timestamp,
                "method": entry.method,
                "path": entry.path,
                "status_code": entry.status_code if hasattr(entry, 'status_code') else 0,
                "request_size": entry.request_size if hasattr(entry, 'request_size') else 0,
                "response_size": entry.response_size if hasattr(entry, 'response_size') else 0,
                "duration_ms": entry.duration_ms if hasattr(entry, 'duration_ms') else 0,
            }
            data.append(record)
        
        df = pd.DataFrame(data)
        
        # Feature engineering
        if not df.empty:
            # One-hot encode HTTP methods
            method_dummies = pd.get_dummies(df["method"], prefix="method")
            df = pd.concat([df, method_dummies], axis=1)
            
            # Extract path components and create features
            df["path_depth"] = df["path"].apply(lambda p: len(p.split("/")))
            df["path_has_query"] = df["path"].apply(lambda p: "?" in p)
            df["path_has_api"] = df["path"].apply(lambda p: "/api/" in p)
            
            # Status code features
            df["is_error"] = df["status_code"] >= 400
            df["is_server_error"] = df["status_code"] >= 500
            
            # Time-based features
            df["hour_of_day"] = df["timestamp"].dt.hour
            df["day_of_week"] = df["timestamp"].dt.dayofweek
            df["is_weekend"] = df["day_of_week"].isin([5, 6])  # 5=Saturday, 6=Sunday
            
            # Size and duration features
            df["size_ratio"] = df.apply(
                lambda row: row["response_size"] / max(row["request_size"], 1), 
                axis=1
            )
        
        # Drop non-numeric and original categorical columns
        feature_cols = df.select_dtypes(include=["number"]).columns.tolist()
        feature_cols = [col for col in feature_cols if col not in ["timestamp", "method", "path", "status_code"]]
        
        return df[feature_cols], feature_cols
    
    async def train_anomaly_detector(self, entries: List[APILogEntry], contamination: float = 0.05):
        """
        Train an anomaly detection model using Isolation Forest.
        
        Args:
            entries: List of API log entries for training
            contamination: Expected proportion of anomalies in the data
        """
        logger.info(f"Training anomaly detection model with {len(entries)} entries")
        
        # Extract features
        features_df, feature_names = self._extract_features(entries)
        
        if features_df.empty:
            logger.error("No features extracted for training")
            return False
        
        # Train isolation forest model
        model = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_jobs=-1
        )
        
        # Create a pipeline with scaling
        pipeline = Pipeline([
            ('scaler', StandardScaler()),
            ('isolation_forest', model)
        ])
        
        # Fit the model
        pipeline.fit(features_df)
        
        # Save the model
        self.models["anomaly_detector"] = pipeline
        self._save_model("anomaly_detector")
        
        # Test on training data to get a baseline
        predictions = pipeline.predict(features_df)
        anomaly_count = (predictions == -1).sum()
        logger.info(f"Model identified {anomaly_count} anomalies in training data ({anomaly_count/len(entries):.2%})")
        
        return True
    
    async def train_security_classifier(self, entries: List[APILogEntry], labels: List[bool]):
        """
        Train a security threat classifier model.
        
        Args:
            entries: List of API log entries for training
            labels: List of boolean labels (True for security threat, False otherwise)
        """
        if len(entries) != len(labels):
            logger.error(f"Number of entries ({len(entries)}) doesn't match number of labels ({len(labels)})")
            return False
            
        logger.info(f"Training security classifier with {len(entries)} entries")
        
        # Extract features
        features_df, feature_names = self._extract_features(entries)
        
        if features_df.empty:
            logger.error("No features extracted for training")
            return False
        
        # Split data for training and validation
        X_train, X_test, y_train, y_test = train_test_split(
            features_df, labels, test_size=0.2, random_state=42, stratify=labels
        )
        
        # Train random forest classifier
        model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            class_weight="balanced",
            n_jobs=-1
        )
        
        # Create a pipeline with scaling
        pipeline = Pipeline([
            ('scaler', StandardScaler()),
            ('random_forest', model)
        ])
        
        # Fit the model
        pipeline.fit(X_train, y_train)
        
        # Evaluate on test set
        accuracy = pipeline.score(X_test, y_test)
        logger.info(f"Security classifier accuracy: {accuracy:.4f}")
        
        # Save the model
        self.models["security_classifier"] = pipeline
        self._save_model("security_classifier")
        
        return True
    
    async def detect_anomalies(self, entries: List[APILogEntry]) -> List[int]:
        """
        Detect anomalies in API log entries using machine learning.
        
        Args:
            entries: List of API log entries to analyze
            
        Returns:
            List of indices of entries that are anomalies
        """
        if "anomaly_detector" not in self.models:
            logger.warning("No anomaly detection model available")
            return []
            
        # Extract features
        features_df, _ = self._extract_features(entries)
        
        if features_df.empty:
            logger.error("No features extracted for anomaly detection")
            return []
        
        # Get predictions (-1 for anomalies, 1 for normal)
        predictions = self.models["anomaly_detector"].predict(features_df)
        
        # Return indices of anomalies
        anomaly_indices = [i for i, pred in enumerate(predictions) if pred == -1]
        logger.info(f"Detected {len(anomaly_indices)} anomalies in {len(entries)} entries")
        
        return anomaly_indices
    
    async def detect_security_threats(self, entries: List[APILogEntry]) -> List[Dict[str, Any]]:
        """
        Detect potential security threats in API log entries.
        
        Args:
            entries: List of API log entries to analyze
            
        Returns:
            List of dictionaries with threat information
        """
        if "security_classifier" not in self.models:
            logger.warning("No security classifier model available")
            return []
            
        # Extract features
        features_df, _ = self._extract_features(entries)
        
        if features_df.empty:
            logger.error("No features extracted for security threat detection")
            return []
        
        # Get predictions and probabilities
        predictions = self.models["security_classifier"].predict(features_df)
        probabilities = self.models["security_classifier"].predict_proba(features_df)[:, 1]  # Probability of class 1 (threat)
        
        # Create threat information for entries classified as threats
        threats = []
        for i, (pred, prob) in enumerate(zip(predictions, probabilities)):
            if pred:  # If predicted as a threat
                threats.append({
                    "entry_index": i,
                    "probability": float(prob),
                    "method": entries[i].method,
                    "path": entries[i].path,
                    "timestamp": entries[i].timestamp.isoformat()
                })
        
        logger.info(f"Detected {len(threats)} security threats in {len(entries)} entries")
        return threats
    
    async def _run_custom_analyzers(self, entry: APILogEntry, results: Dict[str, List[Dict[str, Any]]]):
        """
        Run custom ML-based analyzers on a single entry.
        
        Args:
            entry: The API log entry to analyze
            results: Dictionary to add analysis results to
        """
        # For ML models, it's more efficient to run batch analysis
        # But we implement this to maintain compatibility with the base Scanner's
        # single-entry analysis approach
        
        # Wrap in a list for feature extraction
        entry_list = [entry]
        features_df, _ = self._extract_features(entry_list)
        
        if features_df.empty:
            return
        
        # Check for anomalies
        if "anomaly_detector" in self.models:
            prediction = self.models["anomaly_detector"].predict(features_df)[0]
            if prediction == -1:  # It's an anomaly
                results["anomalies"].append({
                    "type": "ml_anomaly_detection",
                    "description": "Machine learning model flagged this request as anomalous",
                    "confidence": 0.9  # Isolation Forest doesn't provide probabilities
                })
        
        # Check for security threats
        if "security_classifier" in self.models:
            prediction = self.models["security_classifier"].predict(features_df)[0]
            if prediction:  # It's a security threat
                probability = self.models["security_classifier"].predict_proba(features_df)[0, 1]
                results["security"].append({
                    "type": "ml_security_threat",
                    "description": "Machine learning model identified potential security threat",
                    "confidence": float(probability)
                })
    
    async def batch_analyze(self, entries: List[APILogEntry]) -> List[Dict[str, Any]]:
        """
        Analyze a batch of entries using ML models (more efficient than one-by-one).
        
        Args:
            entries: List of API log entries to analyze
            
        Returns:
            List of analysis results corresponding to each entry
        """
        results = []
        
        # Get anomaly and security predictions in batch
        anomaly_indices = await self.detect_anomalies(entries) if "anomaly_detector" in self.models else []
        security_threats = await self.detect_security_threats(entries) if "security_classifier" in self.models else []
        
        # Map security threats by entry index
        threat_map = {threat["entry_index"]: threat for threat in security_threats}
        
        # Create result for each entry
        for i, entry in enumerate(entries):
            entry_result = {
                "anomalies": [],
                "performance": [],
                "security": []
            }
            
            # Add anomaly results
            if i in anomaly_indices:
                entry_result["anomalies"].append({
                    "type": "ml_anomaly_detection",
                    "description": "Machine learning model flagged this request as anomalous",
                    "confidence": 0.9
                })
            
            # Add security results
            if i in threat_map:
                threat = threat_map[i]
                entry_result["security"].append({
                    "type": "ml_security_threat",
                    "description": "Machine learning model identified potential security threat",
                    "confidence": threat["probability"]
                })
            
            # Add performance results (pending performance prediction model)
            
            results.append(entry_result)
        
        return results
    
    async def process_entries(self, entries: List[APILogEntry], source_type: str = "log", source_name: str = "unknown") -> ScanResult:
        """
        Process multiple log entries and generate a scan result with ML enhancements.
        Overrides the base Scanner's process_entries method to add ML capabilities.
        
        Args:
            entries: List of API log entries to analyze
            source_type: The type of source (log, traffic, webhook)
            source_name: Name or identifier of the source
            
        Returns:
            ScanResult object with analysis results and ML insights
        """
        if not entries:
            logger.warning(f"No entries to process for {source_type}:{source_name}")
            return ScanResult(
                scan_id=f"scan_{datetime.now().strftime('%Y%m%d%H%M%S')}",
                timestamp=datetime.now(),
                source_type=source_type,
                source_name=source_name,
                entries_processed=0,
                anomalies_detected=0,
                performance_issues=0,
                security_concerns=0,
                summary={"error": "No entries to process"}
            )
        
        # For efficiency, perform ML batch analysis first
        logger.info(f"Running ML-based batch analysis on {len(entries)} entries from {source_type}:{source_name}")
        ml_analysis_results = await self.batch_analyze(entries)
        
        # Process entries with the base Scanner's implementation
        # We'll modify the base implementation to inject our ML results later
        base_result = await super().process_entries(entries, source_type, source_name)
        
        # Count ML-detected issues
        additional_anomalies = 0
        additional_security = 0
        
        for result in ml_analysis_results:
            if result["anomalies"]:
                additional_anomalies += len(result["anomalies"])
            if result["security"]:
                additional_security += len(result["security"])
        
        # Update scan result with ML findings
        updated_result = ScanResult(
            scan_id=base_result.scan_id,
            timestamp=base_result.timestamp,
            source_type=base_result.source_type,
            source_name=base_result.source_name,
            entries_processed=base_result.entries_processed,
            anomalies_detected=base_result.anomalies_detected + additional_anomalies,
            performance_issues=base_result.performance_issues,
            security_concerns=base_result.security_concerns + additional_security,
            summary=base_result.summary
        )
        
        # Add ML-specific summary information
        ml_summary = {
            "ml_enhanced": True,
            "ml_models_used": list(self.models.keys()),
            "ml_anomalies_detected": additional_anomalies,
            "ml_security_threats": additional_security,
        }
        
        # Add detailed ML analysis
        if additional_anomalies > 0 or additional_security > 0:
            # Get some example issues for the summary
            ml_summary["example_findings"] = []
            
            # Add example anomalies
            anomaly_examples = []
            for i, result in enumerate(ml_analysis_results):
                if result["anomalies"]:
                    entry = entries[i]
                    anomaly_examples.append({
                        "type": "anomaly",
                        "path": entry.path,
                        "method": entry.method,
                        "timestamp": entry.timestamp.isoformat(),
                        "details": result["anomalies"][0]
                    })
                    if len(anomaly_examples) >= 3:  # Limit to 3 examples
                        break
            
            # Add example security threats
            security_examples = []
            for i, result in enumerate(ml_analysis_results):
                if result["security"]:
                    entry = entries[i]
                    security_examples.append({
                        "type": "security",
                        "path": entry.path,
                        "method": entry.method,
                        "timestamp": entry.timestamp.isoformat(),
                        "details": result["security"][0]
                    })
                    if len(security_examples) >= 3:  # Limit to 3 examples
                        break
            
            ml_summary["example_findings"] = anomaly_examples + security_examples
            
            # Add potential cluster analysis
            if len(entries) > 10 and "anomaly_detector" in self.models:
                ml_summary["pattern_analysis"] = self._perform_pattern_analysis(entries, ml_analysis_results)
        
        # Update the summary with ML information
        updated_result.summary["ml_analysis"] = ml_summary
        
        logger.info(f"Completed ML-enhanced analysis: {updated_result.entries_processed} entries, "
                    f"added {additional_anomalies} anomalies, {additional_security} security threats")
                    
        return updated_result
    
    def _perform_pattern_analysis(self, entries: List[APILogEntry], analysis_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Perform additional pattern analysis on the entries using clustering.
        
        Args:
            entries: List of API log entries
            analysis_results: Corresponding analysis results
            
        Returns:
            Dictionary with pattern analysis results
        """
        # Extract features for clustering
        features_df, _ = self._extract_features(entries)
        
        if features_df.empty:
            return {"error": "No features available for pattern analysis"}
        
        # Identify which entries are anomalies according to our analysis
        anomaly_indices = [
            i for i, result in enumerate(analysis_results)
            if result["anomalies"] or result["security"]
        ]
        
        if not anomaly_indices:
            return {"clusters": 0, "message": "No anomalies to cluster"}
        
        # Extract just the anomalous entries for clustering
        anomaly_features = features_df.iloc[anomaly_indices]
        
        # Scale the features
        scaler = StandardScaler()
        scaled_features = scaler.fit_transform(anomaly_features)
        
        # Cluster the anomalies using DBSCAN
        dbscan = DBSCAN(eps=1.0, min_samples=2)
        clusters = dbscan.fit_predict(scaled_features)
        
        # Count number of meaningful clusters (excluding noise labeled as -1)
        num_clusters = len(set(clusters) - {-1})
        
        # Summarize the clusters
        cluster_summary = {"clusters": num_clusters}
        
        if num_clusters > 0:
            cluster_details = []
            
            # Analyze each cluster
            for cluster_id in range(num_clusters):
                # Get indices within anomaly_indices that belong to this cluster
                cluster_member_indices = [
                    anomaly_indices[i] for i, c in enumerate(clusters) if c == cluster_id
                ]
                
                # Get the original entries for this cluster
                cluster_entries = [entries[i] for i in cluster_member_indices]
                
                # Summarize this cluster
                paths = {}
                methods = {}
                status_codes = {}
                
                for entry in cluster_entries:
                    paths[entry.path] = paths.get(entry.path, 0) + 1
                    methods[entry.method] = methods.get(entry.method, 0) + 1
                    status_codes[entry.status_code] = status_codes.get(entry.status_code, 0) + 1
                
                # Find most common attributes
                most_common_path = max(paths.items(), key=lambda x: x[1])[0] if paths else "N/A"
                most_common_method = max(methods.items(), key=lambda x: x[1])[0] if methods else "N/A"
                
                cluster_details.append({
                    "cluster_id": cluster_id,
                    "size": len(cluster_entries),
                    "most_common_path": most_common_path,
                    "most_common_method": most_common_method,
                    "paths": paths,
                    "methods": methods,
                    "status_codes": status_codes
                })
            
            cluster_summary["cluster_details"] = cluster_details
            
            # Generate potential attack pattern description
            if num_clusters >= 1:
                patterns = []
                for cluster in cluster_details:
                    if cluster["size"] >= 3:  # Only consider reasonably sized clusters
                        pattern_desc = (
                            f"Potential attack pattern detected: {cluster['size']} requests to "
                            f"'{cluster['most_common_path']}' using {cluster['most_common_method']}"
                        )
                        patterns.append(pattern_desc)
                
                if patterns:
                    cluster_summary["potential_attack_patterns"] = patterns
        
        return cluster_summary