# Detection 'Unhealthy' State of Security Recommendations from Microsoft Defender for Cloud on Analytics Rule in Microsoft Sentinel
This Repository provides detection rule when Recommendation of Microsoft Defender for Cloud state was changed to "Unhealthy".

# 1. System Diagram
Configuration image as follows.
![image](https://user-images.githubusercontent.com/55295601/198253654-8857cc7b-a228-4405-a578-be6a7deadd03.png)


# 2. How to import
You can import [template json](https://github.com/hisashin0728/UnhealthyStateRuleSentinel/blob/main/Detect_Unhealthy_State_from_MDFC.json) from Microsoft Sentinel.
Caution: 
 - Requires "Recommendation" table in the target LogAnalytics workspace.
 - Previously you need to configure "Continuous Export" on Microsoft Defender for Cloud to the Sentinel Log Analytics Workspace.

<img width="774" alt="image" src="https://user-images.githubusercontent.com/55295601/196851071-0f1ee2ad-2aac-4e12-84fb-ababd27d73da.png">

# 3. Current KQL Query in Analytics Rule
Current version, here is a Kusto Query in this package.

```
let queryfrequency = 1h;
SecurityRecommendation
| where TimeGenerated > ago(queryfrequency)
| where RecommendationState == "Unhealthy"
| where IsSnapshot == "false" // For Continuous Export without Snapshot
| where Environment == "Azure" //For Azure
| extend
    FirstEvaluationDate = tostring(Properties.status.firstEvaluationDate),
    StatusChangeDate = tostring(Properties.status.statusChangeDate)
| extend SubscriptionId = split(AssessedResourceId, "/",2)[0], ResouceGroup = split(AssessedResourceId, "/",4)[0]
| project TimeGenerated,RecommendationName,RecommendationSeverity,FirstEvaluationDate,StatusChangeDate,AssessedResourceId,SubscriptionId,ResouceGroup
```

If you want to monitor multi-cloud environment, comment out '| where Environment == "Azure"'.

# 4. (Option) Filtering Recommendations via WatchList
I suppose many customers would like to filter specific recommendations that was triggered to "Unhealthy" Status, because normaly ASC (Microsoft Defender for Cloud) generates many recommendation events. If you want to filter and detect alert for specific Recommendations, you can use Watchlist feature for filtering recommendations.

Here is customized package for [template json file](https://github.com/hisashin0728/UnhealthyStateRuleSentinel/blob/main/Detect_Unhealthy_State_from_MDFC_watchlist.json).
You can easily upload and import customized analytics rule on Microsoft Sentinel.

After importing template json, you need to create two watchlists.

1. "ASC_Reco" watchlist for filtering recommendations.

Here is a [sample CSV for Watchlist](https://github.com/hisashin0728/UnhealthyStateRuleSentinel/commit/15b75c8900d98194012e68f30752ddb6a87f1371).

```csv
ASC_Reco
TLS should be updated to the latest version for API apps
TLS should be updated to the latest version for function apps
TLS should be updated to the latest version for web apps
Microsoft Defender for servers should be enabled
Microsoft Defender for Containers should be enabled
Microsoft Defender for Azure SQL Database servers should be enabled
Microsoft Defender for DNS should be enabled
Microsoft Defender for open-source relational databases should be enabled
Microsoft Defender for Resource Manager should be enabled
Microsoft Defender for SQL on machines should be enabled on workspaces
Microsoft Defender for SQL servers on machines should be enabled
Microsoft Defender for SQL should be enabled for unprotected Azure SQL servers
Microsoft Defender for SQL should be enabled for unprotected SQL Managed Instances
Microsoft Defender for Storage should be enabled
Microsoft Defender for Key Vault should be enabled
```

2. "testwatchlist" for mapping Subscription ID to Subscription name.

Here is a [sample CSV for watchlist](https://github.com/hisashin0728/UnhealthyStateRuleSentinel/blob/main/watchlistsub.csv).
This csv file is used by analytics rule which will notify subscription name on incident alert.

```csv
SubscriptionId,SubDescription
11111111-eec5-4873-a79c-84ed72c481a2,MySubscription-Prod
11112222-eec5-4873-a79c-84ed72c481a2,MySubscription-Dev
11113333-eec5-4873-a79c-84ed72c481a2,MySubscription-Sandbox
```

As for custom analytics query, you cahh check the watchlist version of this package.

```
let ASC_Rec_watchlist = (_GetWatchlist('ASC_Reco') | project ASC_Reco);

SecurityRecommendation
| where TimeGenerated > ago(queryfrequency)
| where RecommendationState == "Unhealthy"
| where IsSnapshot == "false" // For Continuous Export without Snapshot
| where Environment == "Azure" //For Azure
| where RecommendationName in (ASC_Rec_watchlist)
| extend
    FirstEvaluationDate = tostring(Properties.status.firstEvaluationDate),
    StatusChangeDate = tostring(Properties.status.statusChangeDate)
| extend
    SubscriptionId = split(AssessedResourceId, "/",2)[0],
    ResouceGroup = split(AssessedResourceId, "/",4)[0]
| extend tostring(SubscriptionId)
| lookup kind=leftouter _GetWatchlist('testwatchlist') on $left.SubscriptionId == $right.SearchKey
| project TimeGenerated,RecommendationName,RecommendationSeverity,FirstEvaluationDate,StatusChangeDate,AssessedResourceId,SubscriptionId,ResouceGroup,SubDescription
```

The customized package contains custom event parameters for Subscription Name.
![image](https://user-images.githubusercontent.com/55295601/202185960-31674c04-0090-486d-b4c7-238e6cb19ffe.png)

Customized package notify alert with {{RecommendationName}} and {{SubDescription}}.
![image](https://user-images.githubusercontent.com/55295601/202186353-573274fa-4655-45a5-8ef5-981404840a63.png)

The Incident Alerts is included in Subscription name that is customized in watchlist by customer.
This would be useful for secuity operator who manage many subscriptions.

![image](https://user-images.githubusercontent.com/55295601/202324550-4bd548cb-a64f-4030-8c88-0b555c37388b.png)


# 5. CurrentParameter
Here is a current parameter on this package.

|  Parameter  |  Value  | Description |
| ---- | ---- | ---- |
|  queryfrequency  |  1h  | |
| RecommendationName | | Recommendation Name from Microsoft Defender for Cloud |
| RecommendationSeverity | High/Middle/Low | Recommendation Severity |
| FirstEvaluationDate |  | First Evaluation Date by Azure Policy |
| StatusChangeDate |  | Status Change Date by Azure Policy |
