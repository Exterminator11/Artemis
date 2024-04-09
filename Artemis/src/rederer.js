
const io = require('socket.io-client')
const socket=io('http://localhost:8000')

socket.on('connect',()=>{
  console.log("Collecting logs...")
})

socket.on('data_event2',(data)=>{
  data=JSON.parse(data)
  prediction=data.prediction
  console.log(prediction)
  console.log(data.src_ip)
  console.log(data.dst_ip)
  console.log(data.dst_port)
})

socket.on('disconnect',()=>{
  console.log('disconnected from server')
})