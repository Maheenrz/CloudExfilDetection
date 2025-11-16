import streamlit as st
import pandas as pd
import numpy as np
from faker import Faker
import random
from datetime import datetime, timedelta
import plotly.express as px
import plotly.graph_objects as go
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
import requests
import json
import time

# Page Configuration
st.set_page_config(
    page_title="SOC Copilot - Cloud Security Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #FF4B4B;
        text-align: center;
        padding: 1rem;
        background: linear-gradient(90deg, #1e3a8a 0%, #dc2626 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1.5rem;
        border-radius: 10px;
        color: white;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    .alert-box {
        background: #fee2e2;
        border-left: 4px solid #dc2626;
        padding: 1rem;
        border-radius: 5px;
        margin: 1rem 0;
    }
    .info-box {
        background: #dbeafe;
        border-left: 4px solid #3b82f6;
        padding: 1rem;
        border-radius: 5px;
        margin: 1rem 0;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'df' not in st.session_state:
    st.session_state.df = None
if 'chat_history' not in st.session_state:
    st.session_state.chat_history = []
if 'model' not in st.session_state:
    st.session_state.model = None
if 'anomaly_explanations' not in st.session_state:
    st.session_state.anomaly_explanations = {}

# =================================
# DATA GENERATION & PREPROCESSING
# =================================

@st.cache_data
def generate_cloud_logs(num_rows=11000):
    """Generate synthetic cloud logs with anomalies"""
    fake = Faker()
    users = [f"user_{i}" for i in range(1, 51)]
    actions = ["upload", "download", "delete", "login", "logout"]
    regions_normal = ["us-east-1", "eu-west-3", "ap-south-1"]
    regions_anomalous = ["cn-north-1", "ru-central-1", "sa-east-1"]
    devices = ["laptop", "mobile", "tablet", "desktop"]
    
    logs = []
    
    # Normal logs (97%)
    for _ in range(num_rows):
        logs.append([
            fake.date_time_between(start_date='-90d', end_date='now'),
            random.choice(users),
            random.choice(actions),
            round(abs(np.random.normal(loc=40, scale=25)), 2),
            random.choice(regions_normal),
            fake.ipv4_public(),
            random.choice(devices),
            0
        ])
    
    # Anomaly Type 1: Large Downloads (2%)
    for _ in range(int(num_rows * 0.02)):
        suspicious_time = fake.date_time_between(start_date='-90d', end_date='now')
        suspicious_time = suspicious_time.replace(hour=random.choice([2,3,4]))
        logs.append([
            suspicious_time,
            random.choice(users),
            "download",
            random.uniform(800, 3000),
            random.choice(regions_normal),
            fake.ipv4_public(),
            random.choice(devices),
            1
        ])
    
    # Anomaly Type 2: Foreign Region Login (1%)
    for _ in range(int(num_rows * 0.01)):
        logs.append([
            fake.date_time_between(start_date='-90d', end_date='now'),
            random.choice(users),
            "login",
            0,
            random.choice(regions_anomalous),
            fake.ipv4_public(),
            random.choice(devices),
            1
        ])
    
    # Anomaly Type 3: Odd Hours Activity (1%)
    for _ in range(int(num_rows * 0.01)):
        timestamp = fake.date_time_between(start_date='-90d', end_date='now')
        timestamp = timestamp.replace(hour=random.choice([2,3,4]))
        logs.append([
            timestamp,
            random.choice(users),
            random.choice(["delete", "upload", "download"]),
            random.uniform(20, 300),
            random.choice(regions_normal),
            fake.ipv4_public(),
            random.choice(devices),
            1
        ])
    
    df = pd.DataFrame(logs, columns=[
        "timestamp", "user_id", "action", "data_size_mb",
        "region", "ip_address", "device_type", "anomaly_label"
    ])
    
    return df

@st.cache_data
def preprocess_data(df):
    """Preprocess and engineer features"""
    df = df.copy()
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    
    # Time-based features
    df['hour'] = df['timestamp'].dt.hour
    df['day_of_week'] = df['timestamp'].dt.dayofweek
    df['day'] = df['timestamp'].dt.day
    df['month'] = df['timestamp'].dt.month
    df['is_weekend'] = df['day_of_week'].apply(lambda x: 1 if x >= 5 else 0)
    
    # Encoding categoricals
    label_cols = ["user_id", "action", "region", "ip_address", "device_type"]
    encoders = {}
    
    for col in label_cols:
        enc = LabelEncoder()
        df[col + '_encoded'] = enc.fit_transform(df[col])
        encoders[col] = enc
    
    return df, encoders

@st.cache_resource
def train_model(df):
    """Train Isolation Forest model"""
    feature_cols = [
        "user_id_encoded", "action_encoded", "data_size_mb", "region_encoded",
        "ip_address_encoded", "device_type_encoded", "hour",
        "day_of_week", "is_weekend"
    ]
    
    X = df[feature_cols]
    
    model = IsolationForest(
        n_estimators=250,
        contamination=0.04,
        random_state=42,
        bootstrap=True
    )
    
    model.fit(X)
    
    # Predict anomalies
    predictions = model.predict(X)
    df['predicted_anomaly'] = predictions
    df['predicted_anomaly'] = df['predicted_anomaly'].apply(lambda x: 1 if x == -1 else 0)
    
    # Get anomaly scores
    df['anomaly_score'] = -model.score_samples(X)
    
    return model, df

# ===========================
# AI ASSISTANT FUNCTIONS
# ===========================

def call_megallm_api(prompt, api_key, model="gpt-4o-mini"):
    """Call MegaLLM API for AI assistant"""
    try:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}"
        }
        
        data = {
            "model": model,
            "messages": [
                {"role": "system", "content": "You are a cybersecurity expert assistant helping analyze cloud security logs and anomalies. Provide clear, actionable insights."},
                {"role": "user", "content": prompt}
            ],
            "max_tokens": 500,
            "temperature": 0.7
        }
        
        response = requests.post(
            "https://ai.megallm.io/v1/chat/completions",
            headers=headers,
            json=data,
            timeout=30
        )
        
        if response.status_code == 200:
            return response.json()['choices'][0]['message']['content']
        else:
            return f"Error: {response.status_code} - {response.text}"
    except Exception as e:
        return f"Error calling AI API: {str(e)}"

def generate_anomaly_explanation(row, df):
    """Generate explanation for why a log entry is anomalous"""
    explanations = []
    
    # Check data size
    avg_size = df['data_size_mb'].mean()
    if row['data_size_mb'] > avg_size * 10:
        explanations.append(f"🔴 Unusually large data transfer: {row['data_size_mb']:.2f} MB (avg: {avg_size:.2f} MB)")
    
    # Check time
    if row['hour'] in [2, 3, 4]:
        explanations.append(f"🔴 Activity during suspicious hours: {row['hour']}:00")
    
    # Check region
    if row['region'] in ["cn-north-1", "ru-central-1", "sa-east-1"]:
        explanations.append(f"🔴 Login from unusual region: {row['region']}")
    
    # Check action
    if row['action'] == 'delete' and row['hour'] < 6:
        explanations.append("🔴 Delete action during off-hours")
    
    # Anomaly score
    if row['anomaly_score'] > df['anomaly_score'].quantile(0.95):
        explanations.append(f"🔴 High anomaly score: {row['anomaly_score']:.3f}")
    
    return explanations if explanations else ["Low risk - within normal parameters"]

# ===========================
# MAIN APP
# ===========================

st.markdown('<h1 class="main-header">🛡️ SOC Copilot - Cloud Security Operations Center</h1>', unsafe_allow_html=True)

# Sidebar
with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/security-shield-green.png", width=80)
    st.title("⚙️ Configuration")
    
    # API Configuration
    st.subheader("🤖 AI Assistant Setup")
    api_key = st.text_input("MegaLLM API Key", type="password", help="Get your free API key from megallm.io")
    ai_model = st.selectbox("AI Model", ["gpt-4o-mini", "gpt-3.5-turbo", "claude-3-haiku-20240307"], index=0)
    
    st.markdown("---")
    
    # Data Generation
    st.subheader("📊 Data Configuration")
    num_logs = st.slider("Number of Logs", 5000, 15000, 11000, 1000)
    
    if st.button("🔄 Generate New Dataset", use_container_width=True):
        with st.spinner("Generating cloud logs..."):
            st.session_state.df = generate_cloud_logs(num_logs)
            st.session_state.df, encoders = preprocess_data(st.session_state.df)
            st.session_state.model, st.session_state.df = train_model(st.session_state.df)
            st.success("✅ Dataset generated and model trained!")
            st.rerun()
    
    st.markdown("---")
    
    # Stats
    if st.session_state.df is not None:
        st.subheader("📈 Dataset Stats")
        st.metric("Total Logs", len(st.session_state.df))
        st.metric("Anomalies Detected", st.session_state.df['predicted_anomaly'].sum())
        st.metric("Detection Rate", f"{(st.session_state.df['predicted_anomaly'].sum() / len(st.session_state.df) * 100):.2f}%")

# Initialize data if not exists
if st.session_state.df is None:
    with st.spinner("Initializing SOC Copilot..."):
        st.session_state.df = generate_cloud_logs()
        st.session_state.df, encoders = preprocess_data(st.session_state.df)
        st.session_state.model, st.session_state.df = train_model(st.session_state.df)

df = st.session_state.df

# Main Dashboard Tabs
tab1, tab2, tab3, tab4, tab5 = st.tabs(["🌍 Threat Map", "🔍 Anomaly Detection", "💬 AI Assistant", "📊 Analytics", "🔬 Investigation"])

# ===========================
# TAB 1: THREAT MAP
# ===========================
with tab1:
    st.header("🌍 Real-Time Threat Intelligence Map")
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("🚨 Active Threats", df['predicted_anomaly'].sum(), delta=f"+{random.randint(1,5)} new")
    with col2:
        st.metric("⚠️ High Risk Events", len(df[df['anomaly_score'] > df['anomaly_score'].quantile(0.95)]))
    with col3:
        st.metric("🌐 Regions Monitored", df['region'].nunique())
    with col4:
        st.metric("👥 Active Users", df['user_id'].nunique())
    
    # Region-based threat map
    region_mapping = {
        'us-east-1': {'lat': 37.7749, 'lon': -122.4194, 'name': 'US East'},
        'eu-west-3': {'lat': 48.8566, 'lon': 2.3522, 'name': 'EU West'},
        'ap-south-1': {'lat': 19.0760, 'lon': 72.8777, 'name': 'AP South'},
        'cn-north-1': {'lat': 39.9042, 'lon': 116.4074, 'name': 'CN North'},
        'ru-central-1': {'lat': 55.7558, 'lon': 37.6173, 'name': 'RU Central'},
        'sa-east-1': {'lat': -23.5505, 'lon': -46.6333, 'name': 'SA East'}
    }
    
    # Aggregate anomalies by region
    region_stats = df[df['predicted_anomaly'] == 1].groupby('region').size().reset_index(name='threat_count')
    region_stats['lat'] = region_stats['region'].map(lambda x: region_mapping.get(x, {}).get('lat', 0))
    region_stats['lon'] = region_stats['region'].map(lambda x: region_mapping.get(x, {}).get('lon', 0))
    region_stats['name'] = region_stats['region'].map(lambda x: region_mapping.get(x, {}).get('name', x))
    region_stats['size'] = region_stats['threat_count'] * 10
    
    # Create map
    fig_map = go.Figure()
    
    # Add threat markers
    fig_map.add_trace(go.Scattergeo(
        lon=region_stats['lon'],
        lat=region_stats['lat'],
        text=region_stats.apply(lambda x: f"{x['name']}<br>Threats: {x['threat_count']}", axis=1),
        mode='markers+text',
        marker=dict(
            size=region_stats['size'],
            color=region_stats['threat_count'],
            colorscale='Reds',
            showscale=True,
            colorbar=dict(title="Threat<br>Level"),
            line=dict(width=1, color='white')
        ),
        textposition="top center",
        textfont=dict(size=10, color='white')
    ))
    
    fig_map.update_layout(
        title="Global Threat Distribution",
        geo=dict(
            projection_type='natural earth',
            showland=True,
            landcolor='rgb(20, 20, 30)',
            coastlinecolor='rgb(100, 100, 100)',
            showocean=True,
            oceancolor='rgb(10, 10, 20)',
            bgcolor='rgb(5, 5, 15)'
        ),
        height=500,
        paper_bgcolor='rgb(5, 5, 15)',
        font=dict(color='white')
    )
    
    st.plotly_chart(fig_map, use_container_width=True)
    
    # Recent anomalies
    st.subheader("🚨 Recent Threat Detections")
    recent_anomalies = df[df['predicted_anomaly'] == 1].sort_values('timestamp', ascending=False).head(10)
    
    for idx, row in recent_anomalies.iterrows():
        threat_level = "🔴 HIGH" if row['anomaly_score'] > df['anomaly_score'].quantile(0.95) else "🟡 MEDIUM"
        with st.expander(f"{threat_level} | {row['timestamp']} | User: {row['user_id']} | {row['action'].upper()}"):
            col1, col2 = st.columns(2)
            with col1:
                st.write(f"**Region:** {row['region']}")
                st.write(f"**IP Address:** {row['ip_address']}")
                st.write(f"**Device:** {row['device_type']}")
            with col2:
                st.write(f"**Data Size:** {row['data_size_mb']:.2f} MB")
                st.write(f"**Hour:** {row['hour']}:00")
                st.write(f"**Anomaly Score:** {row['anomaly_score']:.3f}")

# ===========================
# TAB 2: ANOMALY DETECTION
# ===========================
with tab2:
    st.header("🔍 Anomaly Detection Analysis")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Anomaly distribution
        anomaly_counts = df['predicted_anomaly'].value_counts()
        fig_pie = px.pie(
            values=anomaly_counts.values,
            names=['Normal', 'Anomaly'],
            title="Detection Distribution",
            color_discrete_sequence=['#10b981', '#ef4444']
        )
        st.plotly_chart(fig_pie, use_container_width=True)
    
    with col2:
        # Hourly distribution
        hourly_anomalies = df[df['predicted_anomaly'] == 1].groupby('hour').size().reset_index(name='count')
        fig_hourly = px.bar(
            hourly_anomalies,
            x='hour',
            y='count',
            title="Anomaly Distribution by Hour",
            labels={'hour': 'Hour of Day', 'count': 'Anomaly Count'},
            color='count',
            color_continuous_scale='Reds'
        )
        st.plotly_chart(fig_hourly, use_container_width=True)
    
    # Action-based analysis
    col1, col2 = st.columns(2)
    
    with col1:
        action_anomalies = df[df['predicted_anomaly'] == 1].groupby('action').size().reset_index(name='count').sort_values('count', ascending=False)
        fig_actions = px.bar(
            action_anomalies,
            x='action',
            y='count',
            title="Anomalies by Action Type",
            color='count',
            color_continuous_scale='Oranges'
        )
        st.plotly_chart(fig_actions, use_container_width=True)
    
    with col2:
        # Top suspicious users
        user_anomalies = df[df['predicted_anomaly'] == 1].groupby('user_id').size().reset_index(name='count').sort_values('count', ascending=False).head(10)
        fig_users = px.bar(
            user_anomalies,
            x='user_id',
            y='count',
            title="Top 10 Suspicious Users",
            color='count',
            color_continuous_scale='Reds'
        )
        st.plotly_chart(fig_users, use_container_width=True)

# ===========================
# TAB 3: AI ASSISTANT
# ===========================
with tab3:
    st.header("💬 SOC Copilot AI Assistant")
    
    if not api_key:
        st.warning("⚠️ Please enter your MegaLLM API key in the sidebar to use the AI Assistant.")
    else:
        st.success("✅ AI Assistant Ready!")
        
        # Display chat history
        for message in st.session_state.chat_history:
            with st.chat_message(message["role"]):
                st.markdown(message["content"])
        
        # Suggested queries
        st.subheader("💡 Suggested Queries")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("🔍 Analyze recent anomalies", use_container_width=True):
                query = "Analyze the recent anomalies detected in the last 24 hours"
                st.session_state.chat_history.append({"role": "user", "content": query})
        
        with col2:
            if st.button("👤 Most suspicious users", use_container_width=True):
                query = "Who are the most suspicious users and why?"
                st.session_state.chat_history.append({"role": "user", "content": query})
        
        with col3:
            if st.button("🌍 Regional threat analysis", use_container_width=True):
                query = "Analyze threats by geographic region"
                st.session_state.chat_history.append({"role": "user", "content": query})
        
        # Chat input
        if prompt := st.chat_input("Ask the SOC Copilot anything..."):
            # Add user message
            st.session_state.chat_history.append({"role": "user", "content": prompt})
            
            with st.chat_message("user"):
                st.markdown(prompt)
            
            # Generate context from data
            context = f"""
            Current Security Status:
            - Total logs analyzed: {len(df)}
            - Anomalies detected: {df['predicted_anomaly'].sum()}
            - Detection rate: {(df['predicted_anomaly'].sum() / len(df) * 100):.2f}%
            - Time range: Last 90 days
            - Regions monitored: {df['region'].nunique()}
            - Active users: {df['user_id'].nunique()}
            
            Recent anomaly patterns:
            - Top suspicious user: {df[df['predicted_anomaly']==1]['user_id'].value_counts().index[0]} with {df[df['predicted_anomaly']==1]['user_id'].value_counts().values[0]} anomalies
            - Most common anomalous action: {df[df['predicted_anomaly']==1]['action'].value_counts().index[0]}
            - Peak anomaly hour: {df[df['predicted_anomaly']==1]['hour'].value_counts().index[0]}:00
            
            User question: {prompt}
            """
            
            # Get AI response
            with st.chat_message("assistant"):
                with st.spinner("🤔 Analyzing..."):
                    response = call_megallm_api(context, api_key, ai_model)
                    st.markdown(response)
                    st.session_state.chat_history.append({"role": "assistant", "content": response})

# ===========================
# TAB 4: ANALYTICS
# ===========================
with tab4:
    st.header("📊 Advanced Analytics")
    
    # Time series analysis
    df_sorted = df.sort_values('timestamp')
    df_sorted['date'] = df_sorted['timestamp'].dt.date
    daily_anomalies = df_sorted[df_sorted['predicted_anomaly'] == 1].groupby('date').size().reset_index(name='anomaly_count')
    
    fig_timeline = px.line(
        daily_anomalies,
        x='date',
        y='anomaly_count',
        title="Anomaly Trend Over Time",
        labels={'date': 'Date', 'anomaly_count': 'Number of Anomalies'}
    )
    fig_timeline.update_traces(line_color='#ef4444', line_width=3)
    st.plotly_chart(fig_timeline, use_container_width=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Data size distribution
        fig_size = px.histogram(
            df,
            x='data_size_mb',
            color='predicted_anomaly',
            title="Data Transfer Size Distribution",
            labels={'data_size_mb': 'Data Size (MB)', 'predicted_anomaly': 'Status'},
            color_discrete_map={0: '#10b981', 1: '#ef4444'},
            nbins=50
        )
        st.plotly_chart(fig_size, use_container_width=True)
    
    with col2:
        # Device type analysis
        device_stats = df.groupby(['device_type', 'predicted_anomaly']).size().reset_index(name='count')
        fig_device = px.bar(
            device_stats,
            x='device_type',
            y='count',
            color='predicted_anomaly',
            title="Activity by Device Type",
            color_discrete_map={0: '#10b981', 1: '#ef4444'},
            barmode='group'
        )
        st.plotly_chart(fig_device, use_container_width=True)
    
    # Correlation heatmap
    st.subheader("🔥 Feature Correlation Analysis")
    numeric_cols = ['data_size_mb', 'hour', 'day_of_week', 'is_weekend', 'predicted_anomaly', 'anomaly_score']
    corr_matrix = df[numeric_cols].corr()
    
    fig_corr = px.imshow(
        corr_matrix,
        text_auto='.2f',
        title="Feature Correlation Heatmap",
        color_continuous_scale='RdBu_r',
        aspect='auto'
    )
    st.plotly_chart(fig_corr, use_container_width=True)

# ===========================
# TAB 5: INVESTIGATION
# ===========================
with tab5:
    st.header("🔬 Detailed Anomaly Investigation")
    
    st.subheader("🎯 Select an Anomaly to Investigate")
    
    # Filter anomalies
    anomalies_df = df[df['predicted_anomaly'] == 1].sort_values('anomaly_score', ascending=False).reset_index(drop=True)
    
    selected_idx = st.selectbox(
        "Choose anomaly to investigate:",
        range(min(50, len(anomalies_df))),
        format_func=lambda x: f"Anomaly #{x+1} | Score: {anomalies_df.iloc[x]['anomaly_score']:.3f} | User: {anomalies_df.iloc[x]['user_id']} | {anomalies_df.iloc[x]['timestamp']}"
    )
    
    if selected_idx is not None:
        row = anomalies_df.iloc[selected_idx]
        
        # Threat level
        threat_level = "🔴 HIGH RISK" if row['anomaly_score'] > df['anomaly_score'].quantile(0.95) else "🟡 MEDIUM RISK"
        
        st.markdown(f"### {threat_level}")
        st.markdown("---")
        
        # Details in columns
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown("**📋 Event Details**")
            st.write(f"**Timestamp:** {row['timestamp']}")
            st.write(f"**User ID:** {row['user_id']}")
            st.write(f"**Action:** {row['action'].upper()}")
            st.write(f"**Data Size:** {row['data_size_mb']:.2f} MB")
        
        with col2:
            st.markdown("**🌐 Location & Device**")
            st.write(f"**Region:** {row['region']}")
            st.write(f"**IP Address:** {row['ip_address']}")
            st.write(f"**Device Type:** {row['device_type']}")
            st.write(f"**Hour:** {row['hour']}:00")
        
        with col3:
            st.markdown("**📊 Risk Metrics**")
            st.write(f"**Anomaly Score:** {row['anomaly_score']:.3f}")
            st.write(f"**Day of Week:** {['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'][row['day_of_week']]}")
            st.write(f"**Weekend:** {'Yes' if row['is_weekend'] else 'No'}")
            st.write(f"**Month:** {row['month']}")
        
        st.markdown("---")
        
        # AI-powered explanation
        st.subheader("🤖 Why This Is Anomalous")
        explanations = generate_anomaly_explanation(row, df)
        
        for explanation in explanations:
            st.markdown(f"- {explanation}")
        
        # User behavior analysis
        st.markdown("---")
        st.subheader("👤 User Behavior Profile")
        
        user_data = df[df['user_id'] == row['user_id']]
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.metric("Total Activities", len(user_data))
            st.metric("Anomalies Detected", user_data['predicted_anomaly'].sum())
            st.metric("Avg Data Transfer", f"{user_data['data_size_mb'].mean():.2f} MB")
        
        with col2:
            st.metric("Most Common Action", user_data['action'].value_counts().index[0])
            st.metric("Most Used Device", user_data['device_type'].value_counts().index[0])
            st.metric("Risk Score", f"{user_data['anomaly_score'].mean():.3f}")
        
        # User activity timeline
        user_timeline = user_data.sort_values('timestamp')
        fig_user_timeline = px.scatter(
            user_timeline,
            x='timestamp',
            y='data_size_mb',
            color='predicted_anomaly',
            title=f"Activity Timeline for {row['user_id']}",
            labels={'timestamp': 'Time', 'data_size_mb': 'Data Size (MB)'},
            color_discrete_map={0: '#10b981', 1: '#ef4444'},
            hover_data=['action', 'region', 'device_type']
        )
        st.plotly_chart(fig_user_timeline, use_container_width=True)
        
        # Comparison with normal behavior
        st.markdown("---")
        st.subheader("📈 Comparison with Normal Behavior")
        
        col1, col2 = st.columns(2)
        
        with col1:
            # This event vs user average
            st.markdown("**This Event vs User Average**")
            avg_user_size = user_data['data_size_mb'].mean()
            size_diff = ((row['data_size_mb'] - avg_user_size) / avg_user_size * 100) if avg_user_size > 0 else 0
            
            st.metric(
                "Data Size Difference",
                f"{size_diff:+.1f}%",
                delta=f"{row['data_size_mb'] - avg_user_size:.2f} MB"
            )
            
            # Hour comparison
            common_hour = user_data['hour'].mode()[0] if len(user_data['hour'].mode()) > 0 else 12
            st.write(f"**Typical Activity Hour:** {common_hour}:00")
            st.write(f"**This Event Hour:** {row['hour']}:00")
        
        with col2:
            # This event vs global average
            st.markdown("**This Event vs Global Average**")
            avg_global_size = df['data_size_mb'].mean()
            global_diff = ((row['data_size_mb'] - avg_global_size) / avg_global_size * 100) if avg_global_size > 0 else 0
            
            st.metric(
                "Data Size vs Global Avg",
                f"{global_diff:+.1f}%",
                delta=f"{row['data_size_mb'] - avg_global_size:.2f} MB"
            )
            
            # Region comparison
            region_common = df['region'].value_counts().index[0]
            st.write(f"**Most Common Region:** {region_common}")
            st.write(f"**This Event Region:** {row['region']}")
        
        # Automated investigation report
        st.markdown("---")
        st.subheader("📄 Automated Investigation Report")
        
        if api_key and st.button("🤖 Generate AI Investigation Report", use_container_width=True):
            with st.spinner("Generating detailed investigation report..."):
                investigation_prompt = f"""
                Generate a detailed security investigation report for this anomaly:
                
                Event Details:
                - Timestamp: {row['timestamp']}
                - User: {row['user_id']}
                - Action: {row['action']}
                - Data Size: {row['data_size_mb']:.2f} MB
                - Region: {row['region']}
                - IP Address: {row['ip_address']}
                - Device: {row['device_type']}
                - Anomaly Score: {row['anomaly_score']:.3f}
                - Hour: {row['hour']}:00
                
                User Profile:
                - Total activities: {len(user_data)}
                - Anomalies detected: {user_data['predicted_anomaly'].sum()}
                - Average data transfer: {user_data['data_size_mb'].mean():.2f} MB
                
                Context:
                - This event is {size_diff:.1f}% different from user's normal behavior
                - Occurred at {row['hour']}:00 (user typically active at {common_hour}:00)
                
                Please provide:
                1. Risk Assessment (High/Medium/Low)
                2. Key Indicators of Compromise
                3. Potential Attack Vectors
                4. Recommended Actions
                5. Follow-up Investigation Steps
                """
                
                report = call_megallm_api(investigation_prompt, api_key, ai_model)
                
                st.markdown("### 🔍 AI-Generated Investigation Report")
                st.markdown(report)
                
                # Download report button
                report_text = f"""
SOC COPILOT - INVESTIGATION REPORT
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
================================

EVENT DETAILS:
--------------
Timestamp: {row['timestamp']}
User ID: {row['user_id']}
Action: {row['action']}
Data Size: {row['data_size_mb']:.2f} MB
Region: {row['region']}
IP Address: {row['ip_address']}
Device Type: {row['device_type']}
Anomaly Score: {row['anomaly_score']:.3f}
Hour: {row['hour']}:00

AI ANALYSIS:
------------
{report}

================================
Report generated by SOC Copilot
"""
                
                st.download_button(
                    label="📥 Download Report",
                    data=report_text,
                    file_name=f"investigation_report_{row['user_id']}_{row['timestamp'].strftime('%Y%m%d_%H%M%S')}.txt",
                    mime="text/plain"
                )

# ===========================
# FOOTER
# ===========================
st.markdown("---")
st.markdown("""
<div style='text-align: center; color: #888; padding: 2rem;'>
    <p><strong>🛡️ SOC Copilot Dashboard</strong> | Powered by AI & Machine Learning</p>
    <p>Detecting Data Exfiltration Attempts in Cloud Systems</p>
    <p style='font-size: 0.8rem;'>Built with Streamlit • Isolation Forest ML • MegaLLM AI Assistant</p>
</div>
""", unsafe_allow_html=True)