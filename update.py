import asyncio
import aiohttp
import aiofiles
import logging
import xml.dom.minidom

logging.basicConfig(level=logging.INFO)

max_concurrent_requests = 1000
headers = {
    'Content-Type': 'application/soap+xml; charset=utf-8',
    'Cache-Control': 'no-cache',
    'Pragma': 'no-cache',
}

# Updated SOAP envelope data with {} placeholder for UpdateID
data = '''<s:Envelope xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:s="http://www.w3.org/2003/05/soap-envelope">
    <s:Header>
        <a:Action s:mustUnderstand="1">http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/GetExtendedUpdateInfo2</a:Action>
        <a:MessageID>urn:uuid:79626673-9045-4fae-906e-7a3424011d62</a:MessageID>
        <a:To s:mustUnderstand="1">https://fe3cr.delivery.mp.microsoft.com/ClientWebService/client.asmx/secured</a:To>
        <o:Security s:mustUnderstand="1" xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <Timestamp xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
                <Created>2023-07-27T12:12:40.814Z</Created>
                <Expires>2023-07-27T12:17:40.814Z</Expires>
            </Timestamp>
            <wuws:WindowsUpdateTicketsToken wsu:id="ClientMSA" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:wuws="http://schemas.microsoft.com/msus/2014/10/WindowsUpdateAuthorization">
                <TicketType Name="MSA" Version="1.0" Policy="MBI_SSL">
                    <User>dAA9AEUAdwBDAHcAQQBzAE4AMwBCAEEAQQBVAFYAawBpACsAZgBpAEkAMwBpAGsAbgBIAEYARwArAFAASAAyAEUAagBLAFMATQBiAFAARQArAEEAQQBOACsANwBxAFIANwB2AFcAZgBPAGEAUwByADcAUgBQAGUAeQArAGoAQQBOAGEAYwBJAGoAagBSAEMAaQBOAGUARQBPAG4AVQA4AFYATwA5AEsAYwB2AEwARABJAFoALwAxADIAaQByAC8ASgAzAGYAWgBYAE8AbgB1ADMAMQBsAGoARgArADMAaQBrAGEAZwBtAEMASQBEAEEAZgBBAEQAeABGAGQAYwBIAGoAdABGAFQAOQA5AHoAYgBXAG8AVABIAEwAdQB6AFoAagBnAHUAYwA0ADQARQBaADAATgB0AFoAbwBHAEgAZwB4AGEAcABUAHgAOQBFADEAYQBBAFEAWgBOAGMAUwBKADYAcABzAFEATgBjAE0AQQBSAHUAbQBqAGsAawB2AEUAMABiADQARgB5AFgATwBLAHoAMQB4AFQATAB1AEEAawBEAEsAZABWAFkAVQBBADIAWQBBAEEAQQBpAFQAWAB6ADkAVwBRAHMAKwB1AE8AQQBBAEMASwBRAE0AMABWAEkAZQB4ADkAYgBiAHAAbwBPADIAaABkAHIAVAAwAGMAUwAzAFgANwA1AGsATQA1AFIAbgBMAEMANwB2AEwAbABpAEYARABCAHkANgB6AE0AbABFAGUATwBHAG8AdQBBAGkAQQBxAHYARgByAHEAcwBFAE4AUAAzAE0AVQBUADkAcwAzADUAUABDADkAagBYAHQAbwBYAHEAYgA1AFUASgBjAGcAYQBtAE8AVQB1AHQAKwB6AGYAOQBpAGUANgBaADMAQwBBAEoAUgBaAFUAOAAvADYAbgArAEUAcwBoAEEATQBJAEQAMgBiAGoAbgAyADIARwBZAEwAWgAyAHMAagBnADgATgA5AGUAegA5ADIAYgBmADIARgBUAFQANAB6AHgANgBiAEIAdwAwAEUATQBsAHMAWQBnAFMANgBLAG4ARQBoAHkAdQBhAEcAVwBIAEEAUgBGAFoAawBzAGIAeABaAHIATQBhAGsANABTAG8AbQB1AG8ANQBBAFUAUQArAGkAeQB0AEoAWQBuAGoAaQBzADEANQAvAHIAcwA3AEsAUwBkAC8ANQBVAEoAYgBGAEIANwBjAEcAKwBSAGoAWgBMAFgAbABGAEUAWQB1AFUAUwBiAFoAQwBMAFYASwA5AG8AaABBADMATABJAHkAUgBFAE4AQQBGAE8ASABRAHoANQBEAHcAMwBBAFMAVQBOAGMAagBuAEIAUgBsAEIAWAB5AFoAcQBOAHUAcQBhADgAcABqAHgASABSAG0AawBhADkAcwBwADUALwBKAEYAWgBVAFIAWgB3AHgANwBhAE8ASwBRADgAOAB6AHUANABkAEwAWgBOAHkAagB3ADEASwBNADAAVABjAHgAMwB2AFgARQBJAEMAdABTAGcASAB1ADEATQBLAFoAYgBGAGMALwB4AHUAegBYAEwASwBwAHMAbQBSAGsASgBzAG4AcAAxAEEAVQBpAHYAOABhAGMAKwBIADMAUwBWAGEAVwA2AFkAdwAyAEUASQBLAHAAUQBEAGwAdwBWAGoANwBJAHUAeQA2AHkARABkAEQAZwBLAGkAbABjAEUAbQBJAG0AVgA0ACsAZQBTAEkAYwBQADEAMgBxAEkAVwBsAHUAcwAwADAAdwBjAE8ALwBCAGYAOAB4AGcAMABxAHQAVQBKAGsAZwBwAE8AVAB3AFIAdQBhADkAUgBTAHAATwBPAGMANgBNAGUASAAwAHcAYgB5AFMAegBtAEUAeQBDAG0ANQBiAGcAdABTADMANQBpAEYAcABrAE8AYQBvAFMAYwBHADAARQArAEMAMQBiADUASABjAFMAQwBpAE8AawBFADAAVwB1AGoAbQBtAEIAdwBVADAARgBsADEAOABFAFkAbgBSAEEAbABXADkAZwBQAFQARgBYAGMAOABXAEEAMwBUADQAZAByAHYANABzADkAbwBqAE4AaABKAFEAKwA1ADMAWgA5AEMASgBPADYAZQBVAE0ASQBsAHUAdQBPADIALwB1AFQAVQBTAGYATQA3AGwARQBlAFIAdwBMADAATQBLAFUAOABqAGgAdABqAGUANQBpADAAZABxAHgARgA3AEYAcQBRAFMAZABhAHQANQBTADkAOABqADcASwBiADgAMgBtAGkAUwBiAHYAYQB0AE4AVQB4AGEAQQBlAHUAawBlAGoAQwAyAGQAcQBVAEUAbgBzAEoATABrAGsAVwBNAHQAcAB0AHcALwBHAGsAcABVAFYAeQBoAG0AVwBaAHcAOQB0AE0AcABYAEEAVABtADAAaQBoADAATAAyADYATwA0ADgAQQBnAD0APQAmAHAAPQA=</User>
                </TicketType>
                <TicketType Name="AAD" Version="1.0" Policy="MBI_SSL">
                    <User>ZQB5AEoAMABlAFgAQQBpAE8AaQBKAEsAVgAxAFEAaQBMAEMASgBoAGIARwBjAGkATwBpAEoAUwBVAHoASQAxAE4AaQBJAHMASQBuAGcAMQBkAEMASQA2AEkAaQAxAEwAUwBUAE4AUgBPAFcANQBPAFUAagBkAGkAVQBtADkAbQBlAEcAMQBsAFcAbQA5AFkAYwBXAEoASQBXAGsAZABsAGQAeQBJAHMASQBtAHQAcABaAEMASQA2AEkAaQAxAEwAUwBUAE4AUgBPAFcANQBPAFUAagBkAGkAVQBtADkAbQBlAEcAMQBsAFcAbQA5AFkAYwBXAEoASQBXAGsAZABsAGQAeQBKADkALgBlAHkASgBoAGQAVwBRAGkATwBpAEoAbwBkAEgAUgB3AGMAegBvAHYATAAyADkAdQBaAFgATgAwAGIAMwBKAGwATABtADEAcABZADMASgB2AGMAMgA5AG0AZABDADUAagBiADIAMABpAEwAQwBKAHAAYwAzAE0AaQBPAGkASgBvAGQASABSAHcAYwB6AG8AdgBMADMATgAwAGMAeQA1ADMAYQBXADUAawBiADMAZAB6AEwAbQA1AGwAZABDADgAMgBaAGoAUQB3AFkAVwBZAHkAWQBTADEAaQBaAEQAUQB6AEwAVABSAG0ATgBXAFkAdABZAGoASQB4AE4AeQAxAG0ATgBUAFEAMABPAEQATQAxAE4AbQBWAGgATQBXAFUAdgBJAGkAdwBpAGEAVwBGADAASQBqAG8AeABOAGoAawB3AE4ARABVADMATQB6AGcAeABMAEMASgB1AFkAbQBZAGkATwBqAEUAMgBPAFQAQQAwAE4AVABjAHoATwBEAEUAcwBJAG0AVgA0AGMAQwBJADYATQBUAFkANQBNAEQAUQAyAE0AagBNADUATwBDAHcAaQBZAFcATgB5AEkAagBvAGkATQBTAEkAcwBJAG0ARgBwAGIAeQBJADYASQBrAEYAVQBVAFUARgA1AEwAegBoAFYAUQBVAEYAQgBRAFUAYwAwAFYAVQBnADUAVABGAE4ASQBOADAAWgBWAFYAWABSAG0AWgBtAGgAagBSAGsANQBsAE4ASABaAE4AYgBrAFoAcgBVAG0ASgB6AE4ARwBSAFkAYgAxAEoASwBjAEYAWgB0AFQARgBOAHoATwBGAFYAcABRAGsAaABqAE8AWABaAEsATgAzAEYAMQBUAEUAawB4AFEAMABSADMAUgBFAEoAVQBPAEYAbwBpAEwAQwBKAGgAYgBYAEkAaQBPAGwAcwBpAGMASABkAGsASQBpAHcAaQBjAG4ATgBoAEkAbAAwAHMASQBtAEYAdwBjAEcAbABrAEkAagBvAGkATQBqAFkANABOAHoAWQB4AFkAVABJAHQATQBEAE4AbQBNAHkAMAAwAE0ARwBSAG0ATABUAGgAaABPAEcASQB0AFkAegBOAGsAWQBqAEkAMABNAFQAUQAxAFkAagBaAGkASQBpAHcAaQBZAFgAQgB3AGEAVwBSAGgAWQAzAEkAaQBPAGkASQB3AEkAaQB3AGkAWQAyADUAbQBJAGoAcAA3AEkAbgBSAGkAYQBDAEkANgBJAG0AUQB6AFUAbABnAHgAWgBEAE4ATwBaAEYASgBXAFUAWABrADEATwBHAGQAdwBNAHoAVgB6AFQAawBaAHYAWQAyAGMAdwBhAG0AeAA1AEsAMABWAEUAUwAyADQANABRAGwARgBWAFMARQB0AGkAYQBIAE0AOQBJAG4AMABzAEkAbQBSAGwAZABtAGwAagBaAFcAbABrAEkAagBvAGkATQBUAFYAbQBOAGoARQA0AE8AVwBNAHQATgBXAFUAeABNAHkAMAAwAFkAbQBaAG0ATABUAGsAMABaAEQAawB0AE0ARwBVADEAWgBUAEEAMABZAFQASQAxAE4AVABnADIASQBpAHcAaQBaAG0ARgB0AGEAVwB4ADUAWAAyADUAaABiAFcAVQBpAE8AaQBKAEsAUQBVAE4AUABRAGwATQBpAEwAQwBKAG4AYQBYAFoAbABiAGwAOQB1AFkAVwAxAGwASQBqAG8AaQBRADIAOQB1AGIAbQA5AHkASQBpAHcAaQBhAFgAQgBoAFoARwBSAHkASQBqAG8AaQBNAFMANAB4AE4AVABnAHUATQBUAGMANABMAGoARQA0AE0AaQBJAHMASQBtADUAaABiAFcAVQBpAE8AaQBKAEQAYgAyADUAdQBiADMASQBnAFMAawBGAEQAVAAwAEoAVABJAEMAZwB3AE0ARABFAHgATQBqAEUAeABOAFQAYwBwAEkAaQB3AGkAYgAyAGwAawBJAGoAbwBpAFkAVwBWAGoAWQBqAGsAMwBPAEcAWQB0AE8AVwBJADEATwBDADAAMABNAFcARQAzAEwAVABsAGoAWQB6AFkAdABPAFcAVQB3AFkAagBNADUAWgBqAEUAdwBOAFQAWQAxAEkAaQB3AGkAYgAyADUAdwBjAG0AVgB0AFgAMwBOAHAAWgBDAEkANgBJAGwATQB0AE0AUwAwADEATABUAEkAeABMAFQAawAxAE0AagBNADAATgBEAFEAMABMAFQASQB4AE0AVABjAHoATwBEAEkANABOAEMAMAB5AE8AVABJADAATwBUAGcAMQBNAEQAUQB4AEwAVABZAHcATgBqAGMAMwBOAHkASQBzAEkAbgBCADEAYQBXAFEAaQBPAGkASQB4AE0ARABBAHoATQBqAEEAdwBNAEQAVQB3AE0AVQBVAHcATgB6AEkAMABJAGkAdwBpAGMASABkAGsAWAAyAFYANABjAEMASQA2AEkAagBJAHgATwBEAFEAeABPAFMASQBzAEkAbgBCADMAWgBGADkAMQBjAG0AdwBpAE8AaQBKAG8AZABIAFIAdwBjAHoAbwB2AEwAMwBCAHYAYwBuAFIAaABiAEMANQB0AGEAVwBOAHkAYgAzAE4AdgBaAG4AUgB2AGIAbQB4AHAAYgBtAFUAdQBZADIAOQB0AEwAMABOAG8AWQBXADUAbgBaAFYAQgBoAGMAMwBOADMAYgAzAEoAawBMAG0ARgB6AGMASABnAGkATABDAEoAeQBhAEMASQA2AEkAagBBAHUAUQBWAGQAagBRAFUAdAB4AE8AVQBGAGkATQBFADgANQBXAEQAQQB0AGUAVQBaAGYAVgBrAFYAbgBNAFcASgB4AFMASABKAEYAZAAyADgAdwBXAEgATgB6AFkAMABaAE4AYQAxAGQASABaAGsARQAxAGEAMwBGAHcAUwBqAGwAdQBRAFUASQB3AEwAaQBJAHMASQBuAE4AagBjAEMASQA2AEkAbgBWAHoAWgBYAEoAZgBhAFcAMQB3AFoAWABKAHoAYgAyADUAaABkAEcAbAB2AGIAaQBJAHMASQBuAE4AMQBZAGkASQA2AEkAagBaAHoATQBrAGgAZgBVAG0ANQBTAFkAagBOAFEAYgBXAHgARQBYADMAcABLAFUAWABKAEQAWgBtAFYAMQBiADIATQB3AGIAagBSAFAAUwBXAFIATQBkAEgARgBvAFoAawB0AFYATQAzAE0ANABNAEcATQBpAEwAQwBKADAAYQBXAFEAaQBPAGkASQAyAFoAagBRAHcAWQBXAFkAeQBZAFMAMQBpAFoARABRAHoATABUAFIAbQBOAFcAWQB0AFkAagBJAHgATgB5ADEAbQBOAFQAUQAwAE8ARABNADEATgBtAFYAaABNAFcAVQBpAEwAQwBKADEAYgBtAGwAeABkAFcAVgBmAGIAbQBGAHQAWgBTAEkANgBJAGsATgB2AGIAbQA1AHYAYwBpADUASwBRAFUATgBQAFEAbABOAEEAYwAzAFIAMQBaAEcAVgB1AGQAQwA1ADAAWQBXAFoAbABjADIARQB1AFoAVwBSADEATABtAEYAMQBJAGkAdwBpAGQAWABCAHUASQBqAG8AaQBRADIAOQB1AGIAbQA5AHkATABrAHAAQgBRADAAOQBDAFUAMABCAHoAZABIAFYAawBaAFcANQAwAEwAbgBSAGgAWgBtAFYAegBZAFMANQBsAFoASABVAHUAWQBYAFUAaQBMAEMASgAxAGQARwBrAGkATwBpAEoAZgBhAGsAawB3AFgAMQBKAFAATgBHAGcAdwBhAFcAUgBqAFMAMQBkAFEAZQBrAEYAUgBVAEUARgBCAEkAaQB3AGkAZABtAFYAeQBJAGoAbwBpAE0AUwA0AHcASQBpAHcAaQBkADIAbABrAGMAeQBJADYAVwB5AEoAaQBOAHoAbABtAFkAbQBZADAAWgBDADAAegBaAFcAWQA1AEwAVABRADIATwBEAGsAdABPAEQARQAwAE0AeQAwADMATgBtAEkAeABPAFQAUgBsAE8ARABVADEATQBEAGsAaQBYAFgAMAAuAEQAeQBjAEMAcQByAE0AMQA4ADcAcwBPAG8ASABiADUANwBfAG4AZwBNAFYANABjAE4ARABwAEoATABhAEwAQQB2AGYATgA0AEoANwAyAEUARwBSAFEAQQBMAFoAaAB6AFIARwBfAGIAWABOAFIAMwBlAG4AeQBtAG4AdAA0AGsAOABJADYAcgBOAEYAZABsAEYAagBCAGMANgBWAGsATQBwAFcAOABBAGEAZQA0AFgANwBWADYAWgBFAHAASQBSADAAVQBoAE8AcQBoAFcANAB6AHQAMQBXAHoAQgBmAGEANwBoAHkAVABCAC0AMwA1AFIASABfADgAVwA4AGMAawAtAHEAZQBjAHEAdQBfAGUAUABYADgANABKAGEAYgAzAF8ARwBXAFcARgBhAHgAYQBzAFYALQBzAGsASgBvAFoAeABfAG4AZwBCAEIARgBjAE0ASwBlAHkAUAB5AEYAUQBVADAAeQBZAFgAWQBoAGYARQA1AHUAdgBGAEkAMgAxAEgASwBxAGwARwBnAHgAcgB0AFUAUQA4AG8AZwByAHgAOQB3AFgAWQAyADIAMQBEAEMAZgB3AFIAcABNAHoATgB5AFAATQBDADkASgBlAGwATQBMADIAUgBTAHgAVQBpADkAbgBpAE8AdgBIAGQAOQBPAEsAOABQAGIAeQAtAFIAdQA3AC0AQwBBAFUASABKAFcAMwBzAHAATwBQAEYAegBJAEUAbAA1AGgANQBzAGkAZwBSAEUAegBGADcAWAB6AFUAdAA5ADgAQQBhAHEAdgBBAEQAYQBSAFIAcwBaADAAeQAyAFcARABRADIARABOAFIASABfADMAcABmAEgAUgBRAEYAVwBVAHUAdQB4AFcAeAByAFQAMgBVAEQAXwBZAFIAOQAtAFoAZgBRAA==</User>
                </TicketType>
            </wuws:WindowsUpdateTicketsToken>
        </o:Security>
    </s:Header>
    <s:Body>
        <GetExtendedUpdateInfo2 xmlns="http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService">
            <updateIDs>
                <UpdateIdentity>
                    <UpdateID>{}</UpdateID>
                    <RevisionNumber>1</RevisionNumber>
                </UpdateIdentity>
            </updateIDs>
            <infoTypes>
                <XmlUpdateFragmentType>FileUrl</XmlUpdateFragmentType>
                <XmlUpdateFragmentType>FileDecryption</XmlUpdateFragmentType>
                <XmlUpdateFragmentType>EsrpDecryptionInformation</XmlUpdateFragmentType>
                <XmlUpdateFragmentType>PiecesHashUrl</XmlUpdateFragmentType>
                <XmlUpdateFragmentType>BlockMapUrl</XmlUpdateFragmentType>
            </infoTypes>
            <deviceAttributes>E:BranchReadinessLevel=CB&amp;CurrentBranch=ni_release&amp;OEMModel=Dell%20G15%205520&amp;FlightRing=Retail&amp;AttrDataVer=241&amp;InstallLanguage=en-US&amp;OSUILocale=en-US&amp;InstallationType=Client&amp;FlightingBranchName=&amp;OSSkuId=101&amp;App=WU_STORE&amp;ProcessorManufacturer=GenuineIntel&amp;OEMName_Uncleaned=Dell%20Inc.&amp;AppVer=923.614.111.0&amp;OSArchitecture=AMD64&amp;IsFlightingEnabled=0&amp;TelemetryLevel=3&amp;DefaultUserRegion=12&amp;WuClientVer=923.614.111.0&amp;OSVersion=10.0.22621.1992&amp;DeviceFamily=Windows.Desktop</deviceAttributes>
        </GetExtendedUpdateInfo2>
    </s:Body>
</s:Envelope>'''

async def download_update(sem: asyncio.Semaphore, update_id: str) -> None:
    logging.info(f"Starting download for UpdateID: {update_id}")
    async with sem:
        while True:
            try:
                # Download update for the given UpdateID
                logging.info(f"Downloading update for UpdateID {update_id}")
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        'https://fe3cr.delivery.mp.microsoft.com/ClientWebService/client.asmx/secured',
                        headers=headers,
                        data=data.format(update_id),  # Fill in the UpdateID in the SOAP request
                        ssl=False,
                    ) as response:
                        # Prettify the XML string using xml.dom.minidom
                        xml_string = await response.text()
                        pretty_xml = xml.dom.minidom.parseString(xml_string).toprettyxml(indent="    ", encoding="utf-8")

                        # Check if the response contains the <url> element
                        if "<Url>" not in xml_string:
                            logging.warning(f"URL not found in the response for UpdateID {update_id}, skipping")
                            break  # Skip this update and proceed to the next one

                        # Save the XML response to the file if <url> element exists
                        filename = f"{update_id}.xml"
                        async with aiofiles.open(filename, mode='wb') as f:
                            await f.write(pretty_xml)  # Write the bytes directly to the file

                logging.info(f"Download for UpdateID: {update_id} completed")
                break
            except Exception as e:
                logging.exception(f"Failed to download update for UpdateID {update_id}, will retry in 5 seconds")
                await asyncio.sleep(5)

async def main():
    sem = asyncio.Semaphore(max_concurrent_requests)
    queue = asyncio.Queue()

    # Populate the queue with UpdateIDs (you need to replace 'your_file.txt' with the actual file name)
    with open('../output_files/output_1.txt', 'r') as f:
        for line in f:
            update_id = line.strip()  # Read the UpdateID as a string
            await queue.put(update_id)

    tasks = []
    # Create tasks to download updates for each UpdateID
    while not queue.empty():
        update_id = await queue.get()
        task = asyncio.create_task(download_update(sem, update_id))
        tasks.append(task)

    # Wait for all tasks to complete
    await asyncio.gather(*tasks)

if __name__ == '__main__':
    try:
        loop = asyncio.get_event_loop()
        loop.run_until_complete(main())
    finally:
        loop.run_until_complete(asyncio.gather(*asyncio.all_tasks(loop=loop)))
        loop.close()
