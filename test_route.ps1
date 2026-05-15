$remote_ip = '138.124.241.18'
$route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1
$gw = $route.NextHop
$ifIndex = $route.InterfaceIndex
Write-Host "Found route via $gw (interface $ifIndex)"
New-NetRoute -DestinationPrefix "$remote_ip/32" -NextHop $gw -InterfaceIndex $ifIndex -RouteMetric 1
