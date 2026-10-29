import { createApp } from 'vue'
import {
  Alert, App as AApp, Badge, Button, Card, Checkbox, Col, Collapse, ConfigProvider, Descriptions, Divider,
  Drawer, Dropdown, Empty, Form, Input, InputNumber, Layout, Menu, Modal, Popconfirm, Radio, Row, Select,
  Space, Spin, Statistic, Switch, Table, Tabs, Tag, Tooltip, Typography,
} from 'ant-design-vue'
import App from './App.vue'
import { router } from './router.js'
import './style.css'

const app = createApp(App)
for (const c of [
  Alert, AApp, Badge, Button, Card, Checkbox, Col, Collapse, ConfigProvider, Descriptions, Divider, Drawer,
  Dropdown, Empty, Form, Input, InputNumber, Layout, Menu, Modal, Popconfirm, Radio, Row, Select, Space,
  Spin, Statistic, Switch, Table, Tabs, Tag, Tooltip, Typography,
]) app.use(c)
app.use(router)
app.mount('#app')
