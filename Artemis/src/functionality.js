const {spawn}=require('child_process');
const {Notification, ipcRenderer}=require('electron')
const fs=require('fs');
const notifier=require('node-notifier')
const path=require('path')
const sudoPrompt=require('sudo-prompt')
const {app}=require('electron')

let type=process.platform

let ip_address=[]
let portBlock=[]

const block_ip=(ip,port_num)=>{
  if(type!=='darwin'){

  }
  else{
    const scriptPath = '/Users/rachitdas/Desktop/final-app/src/block_ip.scpt';
    let ip1 = ip;
    let port_num1=port_num

    const osascriptCmd = spawn('osascript', [scriptPath, ip1,port_num1]);

    osascriptCmd.stdout.on('data', (data) => {
      console.log(`stdout: ${data}`);
    });

    osascriptCmd.stderr.on('data', (data) => {
      console.error(`stderr: ${data}`);
    });

    osascriptCmd.on('close', (code) => {
      console.log(`Child process exited with code ${code}`);
    });
        // let b_ip=spawn('osascript',[applescript_path_block,ip])
  }
}

const unblock_ip=(ip)=>{
  if(type!=='darwin'){

  }
  else{
    const scriptPath = '/Users/rachitdas/Desktop/final-app/src/unblock_ip.scpt';
    const ip1 = ip;

    const osascriptCmd = spawn('osascript', [scriptPath, ip1]);

    osascriptCmd.stdout.on('data', (data) => {
      console.log(`stdout: ${data}`);
    });

    osascriptCmd.stderr.on('data', (data) => {
      console.error(`stderr: ${data}`);
    });

    osascriptCmd.on('close', (code) => {
      console.log(`Child process exited with code ${code}`);
    });
  }
}


let deleteAllTime=document.getElementById("deletealltime")
let data2
let lastconnection={}
let ports
let bctx,doughchart
let bubbleData
let date,datetime
let src_ip=document.getElementById('src_ip')
let dst_ip=document.getElementById('dst_ip')
let dst_port=document.getElementById('dst_port')
const moreDate=document.getElementById("more_date")
const moreAttack=document.getElementById("more_attack")
let pythonServer
let cic
let renderer
let chartdata=[0,0]
let name=document.getElementById("name")
let email=document.getElementById("mail")
const startButton=document.getElementById("startButton")
const loader=document.getElementById("loaderShow")
const stopButton=document.getElementById("stopButton")
const startContainer=document.getElementById("start-container")
const information=document.getElementById("info")
const benignDetails=document.getElementById("benignDetails")
const maliciousDetails=document.getElementById("maliciousDetails")
const alltimeBenign=document.getElementById("allTimeBenign")
const alltimeMalicious=document.getElementById("allTimeMalicious")
const historyButton=document.getElementById("history-button")
const dashboard=document.getElementById("Dashboard")
const historyPage=document.getElementById("history-page")
const backButton1=document.getElementById("back-button1")
const backButton2=document.getElementById("back-button2")
const clear=document.getElementById("clear-all")
const moreButton=document.getElementById("more-button")
const morePage=document.getElementById("more-page")
let mychart

const displayDate=()=>{
  date=new Date()
  datetime=date.toLocaleString()
  const d=document.getElementById("date")
  d.innerHTML=datetime
}
setInterval(displayDate,1000)

const client2 = () =>{
  const io=require('socket.io-client')
  const socket=io('http://127.0.0.1:8000')

  socket.on('connect',()=>{
    information.innerHTML="Collecting logs..."
    console.log('connected to server')
  })

  socket.on('data_event2',(data)=>{
    console.log(data)
    data2=JSON.parse(data)
    prediction=data2.prediction
    if(ports.hasOwnProperty(data2.dst_port)){
      ports[data2.dst_port]+=1
    }
    else{
      ports[data2.dst_port]=1
    }
    if(prediction.toString().includes('No attack detected')){
      benign+=1
      allbenign+=1
      benignDetails.innerHTML=benign.toString()
      alltimeBenign.innerHTML=allbenign.toString()
    }
    else if(!prediction.toString().includes('Collecting logs...')){
      malicious+=1
      allmalicious+=1
      maliciousDetails.innerHTML=malicious.toString()
      alltimeMalicious.innerHTML=allmalicious.toString()
      notifier.notify({
        title:'Attack Detected on '+datetime,
        message:prediction.toString(),
      })
      addCard(cards,datetime,prediction.toString())
      histt[datetime]=data.toString()
      if(!ip_address.includes(data2.src_ip) && !portBlock.includes(data2.dst_port)){
        ip_address.push(data2.src_ip)
        block_ip(data2.src_ip,data2.dst_port)
      }
    }
    information.innerHTML=prediction.toString()
    src_ip.innerHTML=`source ip : ${data2.src_ip}`
    dst_ip.innerHTML=`destination ip : ${data2.dst_ip}`
    dst_port.innerHTML=`destination port : ${data2.dst_port}`
    moreDate.innerHTML=datetime.toString()
    moreAttack.innerHTML=prediction.toString()
    lastconnection['lastconnection']=[datetime.toString(),prediction.toString()]
    fs.writeFile(path.join(__dirname,'lastconnection.json'),JSON.stringify(lastconnection),(err)=>{
          if(err){
            console.log(err)
            throw err
          }
        })
    })
  socket.on('disconnect',()=>{
    console.log('disconnected from server')
  })
}

let benign,malicious,allbenign,allmalicious
let cards=document.getElementById('cards')
let sh=document.getElementById('show')
let histt

const addCard=(container,d,a)=>{
  let cardContainer=container
  let card=document.createElement('div')
  let date=document.createElement('p')
  let attack=document.createElement('p')
  card.classList.add('card')
  card.classList.add('date')
  card.classList.add('attack')
  date.textContent=d
  attack.textContent=a
  card.appendChild(date)
  card.appendChild(attack)
  cardContainer.appendChild(card)
  sh.innerHTML='Attacks detected'
}


if(fs.existsSync(path.join(__dirname,'details.json'))){
  let details=JSON.parse(fs.readFileSync(path.join(__dirname,'details.json')))
  if(details.date==new Date().toLocaleString().slice(0,10)){
    benign=details.benign
    malicious=details.malicious  
    allbenign=details.allbenign
    allmalicious=details.allmalicious
  }
  else{
    benign=0
    malicious=0
    allbenign=details.allbenign
    allmalicious=details.allmalicious
  }
}
else{
  benign=0
  malicious=0
  allbenign=0
  allmalicious=0
}

if(fs.existsSync(path.join(__dirname,'histt.json'))){
  histt=JSON.parse(fs.readFileSync(path.join(__dirname,'histt.json')))
  for(const key in histt){
    addCard(cards,key,histt[key])
  }
}
else{
  histt={}
}


if(fs.existsSync(path.join(__dirname,'lastconnection.json'))){
  lastconnection=JSON.parse(fs.readFileSync(path.join(__dirname,'lastconnection.json')))
  let [date,attack]=lastconnection['lastconnection']
  moreDate.innerHTML=date.toString()
  moreAttack.innerHTML=attack.toString()
}
else{
  lastconnection={}
}

if(fs.existsSync(path.join(__dirname,'ports.json'))){
  ports=JSON.parse(fs.readFileSync(path.join(__dirname,'ports.json')))
}
else{
  ports={}
}

document.addEventListener('DOMContentLoaded',()=>{
  benignDetails.innerHTML=benign.toString()
  maliciousDetails.innerHTML=malicious.toString() 
  alltimeBenign.innerHTML=allbenign.toString()
  alltimeMalicious.innerHTML=allmalicious.toString()
})

const active=()=>{
  startContainer.style.display='none';
  loader.style.display='flex';
}

const inactive=()=>{
  loader.style.display='none';
  startContainer.style.display='flex';
  startButton.style.marginTop='225px';
}



const startServer=()=>{
  console.log("started server")
  let tc="/Users/rachitdas/Desktop/Artemis.ai/final-a/src/test_cic.py"
  pythonServer=spawn('/opt/homebrew/bin/python3.10',[tc])
  pythonServer.stdout.on('data',(data)=>{
    console.log(data.toString())
  })
  pythonServer.stderr.on('error',(error)=>{
    console.log(error)
  })
  pythonServer.on('exit',(code)=>{
    console.log(`python server exited ${code}`)
  })
}

const startClients=()=>{
  console.log("started client")
  let sni="/Users/rachitdas/Desktop/Artemis.ai/final-a/src/my_cic/sniffer.py"
  cic=spawn('/opt/homebrew/bin/python3',[sni])
  cic.stdout.on('data',(data)=>{
    console.log(data.toString())
  })
  cic.stderr.on('error',(error)=>{
    console.log(error)
  })
  cic.on('exit',(code)=>{
    console.log(code)
  })
  client2()
}


document.addEventListener('DOMContentLoaded',()=>{
  fs.readFile(path.join(__dirname,'user.json'),(err,data)=>{
    name.innerHTML=JSON.parse(data).username
    email.innerHTML=JSON.parse(data).email
  })
})


document.addEventListener('DOMContentLoaded',()=>{
  let ctx=document.getElementById('myChart-1').getContext('2d')
  mychart=new Chart(ctx,{
    label:['Benign','Malicious'],
    type:'pie',
    data:{
      labels:['Benign','Malicious'],
      datasets:[{
      data:chartdata,
      backgroundColor:['rgb(32,32,32,0.7)','rgb(188,100,92,0.7)'],
      borderColor:['rgb(0,0,0)','rgb(255,0,0)'],
      borderWidth:1
    }]
  },
  options: {
    responsive:true,
    scales: {
      y: {
        beginAtZero: true
      }
    }
  },
  plugins: {
    legend: {
      display: true,
      position: 'bottom',
      labels: {
        boxWidth: 15,
        font: {
          size: 12
        }
      }
    }
  }
  })
})


document.addEventListener('DOMContentLoaded',()=>{
  bctx=document.getElementById('bubble-chart').getContext('2d')
  doughchart = new Chart(bctx, {
    type: 'doughnut',
    data: {
      labels:Object.keys(ports),
      datasets: [{
        data:Object.values(ports),
      }],
    },
    options:{

      plugins: {
        legend: {
            position:'top',
            labels:{
              color:"white",
              padding: 30
            }
        }
    }
    }
  });
})


const updateChart=()=>{
  chartdata=[allbenign,allmalicious]
  mychart.data.datasets[0].data=chartdata
  mychart.update()
}

setInterval(updateChart,1000)


const updateChartBubble=()=>{
  bubbleData=Object.values(ports)
  doughchart.data.datasets[0].data=bubbleData
  doughchart.update()
}

setInterval(updateChartBubble,10000)

startButton.addEventListener("click",()=>{
  console.log('Start clicked') 
  active()
  information.style.display='flex';
  information.innerHTML="Scanning now..."
  startServer()
  startClients()
})

document.addEventListener('DOMContentLoaded',()=>{
  stopButton.addEventListener("click",()=>{
    console.log('Stop clicked')
    cic.kill()
    pythonServer.kill()
    inactive()
    information.style.display='none';
    fs.writeFile(path.join(__dirname,'details.json'),JSON.stringify({"date":datetime.slice(0,10),"benign":benign,"malicious":malicious,"allbenign":allbenign,"allmalicious":allmalicious}),(err)=>{
      if(err){
          console.log(err);
          throw err
      }
    })
    fs.writeFile(path.join(__dirname,'hist.json'),JSON.stringify(histt),(err)=>{
      if(err){
        console.log(err)
        throw err
      }
    })
    fs.writeFile(path.join(__dirname,'ports.json'),JSON.stringify(ports),(err)=>{
      if(err){
        console.log(err)
        throw err
      }
    })
  })
  })

historyButton.addEventListener('click',()=>{
  dashboard.style.display='none'
  historyPage.style.display='block'
})

backButton1.addEventListener('click',()=>{
  dashboard.style.display='block'
  historyPage.style.display='none'
})

moreButton.addEventListener('click',()=>{
  dashboard.style.display='none'
  morePage.style.display='block'
})

backButton2.addEventListener('click',()=>{
  dashboard.style.display='block'
  morePage.style.display='none'
})

clear.addEventListener('click',()=>{
  while(cards.firstChild){
    cards.removeChild(cards.firstChild)
  }
  sh.innerHTML='Looks like your PC is safe'
  if(fs.existsSync(path.join(__dirname,'histt.json'))){
    fs.unlinkSync(path.join(__dirname,'histt.json'))
  }
})

deleteAllTime.addEventListener('click',()=>{
  allbenign=0
  allmalicious=0
  ports={}
  alltimeBenign.innerHTML=allbenign.toString()
  alltimeMalicious.innerHTML=allmalicious.toString()
  if(fs.existsSync(path.join(__dirname,'details.json'))){
    fs.unlinkSync(path.join(__dirname,'details.json'))
  }
  if(fs.existsSync(path.join(__dirname,'ports.json'))){
    fs.unlinkSync(path.join(__dirname,'ports.json'))
  }
})