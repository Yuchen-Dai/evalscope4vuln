import { useEffect, useRef, useState } from 'react'
import { Outlet, useLocation } from 'react-router-dom'
import TopNav from '@/components/nav/TopNav'

export default function MainLayout() {
  const location = useLocation()
  const [visible, setVisible] = useState(true)
  const prevPath = useRef(location.pathname)

  useEffect(() => {
    if (prevPath.current !== location.pathname) {
      setVisible(false)
      const timer = setTimeout(() => {
        setVisible(true)
        prevPath.current = location.pathname
      }, 60)
      return () => clearTimeout(timer)
    }
  }, [location.pathname])

  // 报告目录固定为服务端 outputs_root（--outputs），不再提供目录选择器（多用户共享固定目录）
  return (
    <div className="flex flex-col min-h-screen">
      <TopNav />
      <main className="flex-1 max-w-[1600px] mx-auto w-full px-4 py-5 flex flex-col gap-4">
        <div
          key={location.pathname}
          className="page-enter"
          style={{ opacity: visible ? undefined : 0 }}
        >
          <Outlet />
        </div>
      </main>
    </div>
  )
}
