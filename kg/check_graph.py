from config import get_driver, URI

driver = get_driver()
print("Connexion à :", URI)
with driver.session() as s:
    print("Nœuds :", s.run("MATCH (n) RETURN count(n) AS c").single()["c"])
    print("Relations :", s.run("MATCH ()-[r]->() RETURN count(r) AS c").single()["c"])
    print("Contraintes :", len(list(s.run("SHOW CONSTRAINTS"))))
driver.close()