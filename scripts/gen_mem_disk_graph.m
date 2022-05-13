M = csvread("monitor.csv");
X = M(:,1) - M(1,1);
plot(X,M(:,2),X,M(:,3)/1024);
legend("memory", "database", "location", "southeast")
title("state and memory growth for the verkle conversion")
ylabel("MB")
xlabel("seconds")
print("monitor.png", "-dpng")