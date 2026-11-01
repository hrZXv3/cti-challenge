import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parent.parent))
from shared.config import DATA_DIR

import altair as alt
import pandas as pd
import streamlit as st

st.set_page_config(page_title="Dashboard IOC", layout="wide")
st.title("Dashboard des IOC collectés")

df = pd.read_csv(DATA_DIR / "iocs.csv")

malwares = df["malware"].dropna()
malwares = malwares[~malwares.isin(["Unknown malware", "Unknown Loader"])]

col1, col2, col3 = st.columns(3)
col1.metric("IOC uniques", len(df))
col2.metric("Sources", df["source"].nunique())
col3.metric("Familles de malware", malwares.nunique())

st.subheader("Répartition des IOC")
c1, c2 = st.columns(2)
c1.write("Par source")
c1.bar_chart(df["source"].value_counts())
c2.write("Par type")
c2.bar_chart(df["type"].value_counts())

st.subheader("Top 10 des familles de malware")
top = malwares.value_counts().head(10).reset_index()
top.columns = ["famille", "nombre"]
chart = alt.Chart(top).mark_bar().encode(
    x=alt.X("nombre:Q", title="Nombre d'IOC"),
    y=alt.Y("famille:N", sort="-x", title=None),
)
st.altair_chart(chart, use_container_width=True)
st.sidebar.header("Filtres")
liste_sources = sorted(df["source"].unique())
liste_types = sorted(df["type"].unique())
sources = st.sidebar.multiselect("Source", liste_sources, default=liste_sources)
types = st.sidebar.multiselect("Type", liste_types, default=liste_types)
familles = st.sidebar.multiselect("Famille de malware", sorted(malwares.unique()))
recherche = st.sidebar.text_input("Recherche (IOC ou tag)")

filtre = df[df["source"].isin(sources) & df["type"].isin(types)]
if familles:
    filtre = filtre[filtre["malware"].isin(familles)]
if recherche:
    dans_ioc = filtre["ioc"].str.contains(recherche, case=False, na=False, regex=False)
    dans_tags = filtre["tags"].str.contains(recherche, case=False, na=False, regex=False)
    filtre = filtre[dans_ioc | dans_tags]


def defang(ioc):
    return str(ioc).replace("http", "hxxp").replace(".", "[.]")


st.subheader(f"Liste des IOC ({len(filtre)})")
affichage = filtre.copy()
affichage["ioc"] = affichage["ioc"].apply(defang)
st.dataframe(affichage, use_container_width=True, hide_index=True)
