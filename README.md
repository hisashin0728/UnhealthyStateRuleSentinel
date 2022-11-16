# Detection 'Unhealthy' State of Security Recommendations from Microsoft Defender for Cloud on Analytics Rule in Microsoft Sentinel
This Repository provides detection rule when Recommendation of Microsoft Defender for Cloud state was changed to "Unhealthy".

# 1. System Diagram
Configuration image as follows.
![image](https://user-images.githubusercontent.com/55295601/198253654-8857cc7b-a228-4405-a578-be6a7deadd03.png)


# 2. How to import
You can select import button from Microsoft Sentinel.
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
I suppose many customer would like to filter specific recommendations that was triggered to "Unhealthy" Status, because normaly ASC (Microsoft Defender for Cloud) generates many recommendation events. If you want to filter and detect alert for specific Recommendations, you can use Watchlist feature for filtering recommendations.

Here is a sample CSV for Watchlist.

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

Then you will update Kusto Query in Analytics template as follows.

```
let queryfrequency = 1h;
//Watchlist as a variable
let ASC_Rec_watchlist = (_GetWatchlist('ASC_Reco') | project ASC_Reco);

SecurityRecommendation
| where TimeGenerated > ago(queryfrequency)
| where RecommendationState == "Unhealthy"
| where IsSnapshot == "false" // For Continuous Export without Snapshot
| where Environment == "Azure" //For Azure
| where RecommendationName in (ASC_Rec_watchlist)
```

# 5. CurrentParameter
Here is a current parameter on this package.

|  Parameter  |  Value  | Description |
| ---- | ---- | ---- |
|  queryfrequency  |  1h  | |
| RecommendationName | | Recommendation Name from Microsoft Defender for Cloud |
| RecommendationSeverity | High/Middle/Low | Recommendation Severity |
| FirstEvaluationDate |  | First Evaluation Date by Azure Policy |
| StatusChangeDate |  | Status Change Date by Azure Policy |
